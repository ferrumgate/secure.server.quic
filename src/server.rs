#[path = "redis_client.rs"]
mod redis_client;

#[path = "server_config.rs"]
mod server_config;

use std::collections::HashMap;
use std::{fs, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};

use crate::common::{generate_random_string, handle_as_stdin};

use quinn::{Connection, Endpoint, IdleTimeout, RecvStream, SendStream, VarInt};

use crate::ferrum_stream::{
    FerrumProto, FerrumProtoDefault, FerrumReadStream, FerrumStream, FerrumStreamFrame,
    FerrumWriteStream, FrameBytes, FrameNone, FrameStr,
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::ferrum_tun::{FerrumTun, FerrumTunPosix};

#[cfg(any(target_os = "windows"))]
use crate::ferrum_tun::{FerrumTun, FerrumTunWin32};
use redis_client::RedisClient;
use rustls::{Certificate, PrivateKey};

pub use server_config::FerrumServerConfig;

use std::time::{SystemTime, UNIX_EPOCH};
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
    proto: Option<Box<dyn FerrumProto>>,
    connection: Option<quinn::Connection>,
    tun: Option<Box<dyn FerrumTun>>,
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
        let cert =
            rcgen::generate_simple_self_signed(vec!["secure.ferrumgate.com".into()]).unwrap();

        let key = cert.serialize_private_key_der();
        let cert = cert.serialize_der().unwrap();
        fs::create_dir_all(path).context("failed to create certificate directory")?;
        fs::write(cert_path, &cert).context("failed to write certificate")?;
        fs::write(key_path, &key).context("failed to write private key")?;

        let key = rustls::PrivateKey(key);
        let cert = rustls::Certificate(cert);
        (vec![cert], key)
    };
    Ok(FerrumServerCertChain { certs, key })
}

type Map = HashMap<String, usize>;
struct RateLimitCheck {
    limits: [Map; 2],
    limits_index: usize,
    max_try: usize,
    max_window_ms: u64,
}
impl RateLimitCheck {
    pub fn new(max_try: usize, max_window_ms: u64) -> Self {
        Self {
            limits: [HashMap::new(), HashMap::new()],
            limits_index: usize::MAX,
            max_try,
            max_window_ms,
        }
    }
    /**
     * check if ip limit is ove
     */
    pub fn is_limit_over(&mut self, ip: &str, now: Option<u128>) -> bool {
        let now = now.unwrap_or(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_millis(0))
                .as_millis(),
        );
        let index = usize::try_from((now / u128::from(self.max_window_ms)) % 2).unwrap_or(0);
        if index != self.limits_index {
            self.limits[index].clear();
            self.limits_index = index;
        }
        let map = &mut self.limits[index];
        match map.get(ip) {
            None => {
                map.insert(ip.to_string(), 1usize);
                false
            }
            Some(a) => {
                if *a >= self.max_try {
                    true
                } else {
                    map.insert(ip.to_string(), *a + 1);
                    false
                }
            }
        }
    }
}
pub struct FerrumServer {
    options: FerrumServerConfig,
    endpoint: Endpoint,
    ratelimit: RateLimitCheck,
}

impl FerrumServer {
    pub fn new(options: FerrumServerConfig, certs: FerrumServerCertChain) -> Result<Self> {
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs.certs, certs.key)?;
        server_crypto.alpn_protocols = crate::common::ALPN_QUIC_HTTP
            .iter()
            .map(|&x| x.into())
            .collect();
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
        transport_config.max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_millis(options.idle_timeout)).unwrap(),
        ));

        let endpoint = quinn::Endpoint::server(server_config, options.listen)?;
        Ok(FerrumServer {
            options,
            endpoint,
            ratelimit: RateLimitCheck::new(60, 60 * 1000),
        })
    }

    #[allow(unused)]
    pub fn create_server_cert_chain(option: &FerrumServerConfig) -> Result<FerrumServerCertChain> {
        create_certs_chain(option)
    }
    async fn kill_connection(conn: quinn::Connecting) -> Result<()> {
        let _connection = conn.await?;
        //connection.close(0u32.into(), b"done");
        Ok(())
    }

    pub async fn listen(&mut self, cancel_token: CancellationToken) {
        info!("starting listening on {}", self.options.listen);
        let is_stdin_out = self.options.stdinout;
        let cancel_token = cancel_token.clone();

        while let Some(conn) = select! {
            conn=self.endpoint.accept()=>{conn},
            _=cancel_token.cancelled()=>{None}
        } {
            debug!("connection incoming");
            let client_ip = conn.remote_address().ip().to_string();
            if self.ratelimit.is_limit_over(client_ip.as_str(), None) {
                warn!("ratelimit for client ip: {}", client_ip);
                tokio::spawn(async move {
                    let _ = FerrumServer::kill_connection(conn).await;
                });

                continue;
            }

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
                    read_buf: vec![0u8; 1600],
                    tun: None,
                };
                let res = timeout(
                    Duration::from_millis(options.connect_timeout),
                    FerrumServer::handle_connection(conn),
                )
                .await;

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
                                client.proto = Some(Box::new(FerrumProtoDefault::new(1600)));
                                client.read_stream = Some(Box::new(recv));
                                client.write_stream = Some(Box::new(send));
                                client.connection = Some(conn);

                                let _ =
                                    FerrumServer::handle_client(&mut client, cancel_token, 5000)
                                        .await;
                                warn!("closing connection {}", client.client_ip);
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
        debug!("stream opened {}", connection.remote_address());
        Ok((send, recv, connection))
    }

    fn create_tun_device(client: &mut FerrumClient) -> Result<()> {
        if client.tun.is_some() {
            return Ok(());
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let tun = FerrumTunPosix::new(4096).map_err(|e| {
            error!("tun create failed: {}", e);
            e
        })?;
        #[cfg(any(target_os = "windows"))]
        let tun = FerrumTunWin32::new(4096).map_err(|e| {
            error!("tun create failed: {}", e);
            e
        })?;
        client.tun = Some(Box::new(tun));
        info!(
            "ferrum_tunnel_opened: {}",
            client.tun.as_ref().unwrap().get_name()
        );
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn handle_client(
        client: &mut FerrumClient,
        cancel_token: CancellationToken,
        timeout_ms: u64,
    ) -> Result<()> {
        let hello_msg = timeout(
            Duration::from_millis(timeout_ms),
            FerrumStream::read_next_frame(
                client.read_buf.as_mut(),
                client.proto.as_mut().unwrap().as_mut(),
                client.read_stream.as_mut().unwrap().as_mut(),
                &cancel_token,
            ),
        )
        .await
        .map_err(|err| {
            //test h1
            error!("hello msg timeout {}", err);
            err
        })?;
        let hello_msg = hello_msg.map_err(|err| {
            //test h2
            error!("parsing error");
            err
        })?;
        match hello_msg {
            FerrumStreamFrame::FrameBytes(_a) => {
                //test h3
                error!("protocol error");
                return Err(anyhow!("protocol error"));
            }
            FerrumStreamFrame::FrameStr(a) => {
                // test h4
                if a.data != "hello" {
                    error!("protocol error");
                    return Err(anyhow!("protocol error"));
                }
                debug!("hello msg received");
            }
        }

        //let _stdin = tokio::io::stdin();
        let ctoken1 = cancel_token.clone();
        let tunnel = generate_random_string(63);
        info!("open tunnel: {}", tunnel);
        //this block is important for droping
        {
            let mut redis = RedisClient::new(
                client.redis_host.as_str(),
                client.redis_user.clone(),
                client.redis_pass.clone(),
            );
            let _ = redis.connect().await.map_err(|err| {
                //test r1
                error!("connecting to redis failed {}", err);
                err
            })?;

            redis
                .execute(
                    tunnel.as_str(),
                    client.client_ip.as_str(),
                    client.gateway_id.as_str(),
                    300000,
                    60000_u64,
                )
                .await?;
            let mut frame = client
                .proto
                .as_ref()
                .unwrap()
                .encode_frame_str(format!("ferrum_open:tunnel= {}", tunnel).as_str())?;

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
                //test r3
                error!("could not authenticate {}", client.client_ip);
                return Err(anyhow!("could not authenticate {}", client.client_ip));
            }
        }
        debug!("authentication completed for {}", client.client_ip);
        FerrumServer::create_tun_device(client)?;

        //this block is important for destroy redis connection
        {
            let mut redis = RedisClient::new(
                client.redis_host.as_str(),
                client.redis_user.clone(),
                client.redis_pass.clone(),
            );
            let _ = redis.connect().await.map_err(|err| {
                //test r1
                error!("connecting to redis failed {}", err);
                err
            })?;
            let tun_name = client.tun.as_ref().unwrap().get_name();
            redis
                .execute_tun(tunnel.as_str(), tun_name, 60000_u64)
                .await?;
        }
        let mut frame = client
            .proto
            .as_ref()
            .unwrap()
            .encode_frame_str("ferrum_tunnel_confirmed:")?;
        //test r4
        client
            .write_stream
            .as_mut()
            .unwrap()
            .write_ext(frame.data.as_mut())
            .await?;

        //output

        // let _array = &mut [0u8; 1024];

        //let mut stdout = tokio::io::stderr();
        let mut last_error: Option<anyhow::Error> = None;
        loop {
            debug!("waiting for input");
            select! {
                _= ctoken1.cancelled()=>{

                    warn!("cancelled");
                    //last_error=Some(anyhow!("wait canceled"));
                    break;
                },
                tunresp=client.tun.as_mut().unwrap().read()=>{//tun interface readed

                    match tunresp {

                        Err(e) => {
                            //test h6
                            error!("tun read error {}", e);
                            last_error=Some(e);
                            break;
                        }
                        Ok(data)=>{
                            //test h7
                            debug!("readed from tun {} and streamed",data.data.len());
                            let res=FerrumStream::write_bytes(data.data.as_ref(),
                            client.proto.as_mut().unwrap().as_mut(),
                            client.write_stream.as_mut().unwrap().as_mut()).await;

                            if let Err(e) =res {
                                //test h8
                                    error!("stream write error {}", e);
                                    last_error=Some(e);
                                    break;
                            }
                        }
                    }

                },
                resp = client.read_stream.as_mut().unwrap().as_mut().read_ext(client.read_buf.as_mut())=>{

                    match resp{
                        Err(e) => {
                            //test h9
                            error!("stream read error {}", e);
                            last_error=Some(e);
                            break;
                        },
                        Ok(response) =>{

                            match response {
                                None | Some(0) => {
                                    //test h10
                                    info!("stream finished");
                                    last_error=Some(anyhow!("stream closed"));
                                    break;
                                },
                                Some(data) => {
                                    debug!("data received from stream {}", data);
                                    client.proto.as_mut().unwrap().write(&client.read_buf[..data]);


                                    let mut break_main_loop=true;
                                    loop
                                    {
                                        let res=client.proto.as_mut().unwrap().decode_frame();
                                        match res{
                                            Err(e) =>{
                                                //test h11
                                                error!("tun parse frame failed {}", e);
                                                last_error=Some(e);
                                                break;
                                            }
                                            Ok(res_frame)=>{
                                                match res_frame {
                                                    FrameNone=> {//no frame detected, follow stream
                                                        //test h12
                                                        //last_error=Some(anyhow!("no frame"));
                                                        debug!("no frame detected");
                                                        break_main_loop=false;
                                                        break;
                                                    },
                                                    FrameStr(_)=>{
                                                        //test h13
                                                        warn!("not valid frame");
                                                        last_error=Some(anyhow!("str frame"));
                                                        break;

                                                    },
                                                    FrameBytes(res_data)=>{

                                                        debug!("write tun packet size is: {}",res_data.data.len());
                                                        let res=client.tun.as_mut().unwrap().write(&res_data.data).await;
                                                        match res{
                                                            Err(e) => {
                                                                //test h14
                                                                error!("tun write failed {}", e);
                                                                last_error=Some(e);
                                                                break;
                                                            },
                                                            _=>{
                                                                //test h15
                                                                break_main_loop=false;
                                                            }
                                                        }

                                                    }
                                                }
                                            }
                                        }
                                    }
                                 if break_main_loop {//error occured
                                    break;
                                 }
                                }

                            }
                        }
                    }
                }
            }
        }

        //let _ = tokio::io::stdout().flush().await;

        debug!("closing everything");
        if last_error.is_none() {
            Ok(())
        } else {
            let err = last_error.unwrap();
            if cfg!(debug_assertions) {
                eprintln!("{}", err);
            } else {
                debug!("{}", err);
            }
            Err(err)
        }
    }

    #[allow(unused)]
    pub fn close(&self) {
        self.endpoint.wait_idle();
        self.endpoint.close(VarInt::from_u32(0_u32), b"close");
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::ferrum_stream::{
        FerrumFrame, FerrumFrameBytes, FERRUM_FRAME_BYTES_TYPE, FERRUM_FRAME_STR_TYPE,
    };
    use crate::ferrum_tun::FerrumTunFrame;
    use async_trait::async_trait;
    use bytes::BytesMut;
    use std::sync::Mutex;

    #[tokio::test]
    async fn ratelimit() {
        let mut rate = RateLimitCheck::new(10, 100);
        let client = "1.1.1.1";
        let result = rate.is_limit_over(client, None);
        assert_eq!(result, false);
        let res1 = rate.limits[0].get(client).unwrap_or(&0usize);
        let res2 = rate.limits[1].get(client).unwrap_or(&0usize);
        assert_eq!(*res1 + *res2, 1);
        let result = rate.is_limit_over(client, None);
        assert_eq!(result, false);
        let res1 = rate.limits[0].get(client).unwrap_or(&0usize);
        let res2 = rate.limits[1].get(client).unwrap_or(&0usize);
        assert_eq!(*res1 + *res2, 2);
        for i in 2..10 {
            let result = rate.is_limit_over(client, None);
            assert_eq!(result, false);
            let res1 = rate.limits[0].get(client).unwrap_or(&0usize);
            let res2 = rate.limits[1].get(client).unwrap_or(&0usize);
            assert_eq!(*res1 + *res2, i + 1);
        }
        tokio::time::sleep(Duration::from_millis(102)).await;
        let mut res = true;
        for _i in 0..50 {
            let result = rate.is_limit_over(client, None);
            res = res & result;
        }
        assert_eq!(result, false);
    }

    #[tokio::test]
    async fn ratelimit_check_maps() {
        let mut rate = RateLimitCheck::new(2, 10);
        let client = "1.1.1.1";
        let result = rate.is_limit_over(client, Some(0));
        assert_eq!(result, false);
        let res1 = rate.limits[0].get(client).unwrap();
        assert_eq!(*res1, 1);

        let result = rate.is_limit_over(client, Some(0));
        assert_eq!(result, false);
        let res1 = rate.limits[0].get(client).unwrap();
        assert_eq!(*res1, 2);

        let result = rate.is_limit_over(client, Some(0));
        assert_eq!(result, true);
        let res1 = rate.limits[0].get(client).unwrap();
        assert_eq!(*res1, 2);
        //lets change time
        let result = rate.is_limit_over(client, Some(11));
        assert_eq!(result, false);
        let res1 = rate.limits[0].get(client).unwrap();
        assert_eq!(*res1, 2); // this map not changed
        let res1 = rate.limits[1].get(client).unwrap();
        assert_eq!(*res1, 1); // this map changed

        //lets change time again
        let result = rate.is_limit_over(client, Some(0));
        assert_eq!(result, false);
        let res1 = rate.limits[0].get(client).unwrap();
        assert_eq!(*res1, 1); //this map cleared
        let res1 = rate.limits[1].get(client).unwrap();
        assert_eq!(*res1, 1);
    }

    fn create_client() -> FerrumClient {
        FerrumClient {
            client_ip: "1.2.3.4".to_string(),
            gateway_id: "abc".to_string(),
            redis_host: "localhost".to_string(),
            connection: None,
            proto: None,
            read_buf: vec![0u8; 2048],
            read_stream: None,
            redis_pass: None,
            redis_user: None,
            write_stream: None,
            tun: None,
        }
    }
    #[tokio::test]
    async fn test_server_handle_client_timeout() {
        //test h1

        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                tokio::time::sleep(Duration::from_millis(1000)).await;
                Ok(Some(0))
            }
        }

        struct MockFerrumProto {
            real: FerrumProtoDefault,
        }
        impl MockFerrumProto {
            pub fn new(buf_size: usize) -> Self {
                MockFerrumProto {
                    real: FerrumProtoDefault::new(buf_size),
                }
            }
        }
        impl FerrumProto for MockFerrumProto {
            fn write(&mut self, buf: &[u8]) {
                self.real.write(buf);
            }
            fn decode_frame(&mut self) -> Result<FerrumFrame> {
                return self.real.decode_frame();
            }
            fn encode_frame_str(&self, _val: &str) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_str(_val)
            }
            fn encode_frame_bytes(&self, _val: &[u8]) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_bytes(_val)
            }
        }

        let mut client = create_client();
        let cancel_token = CancellationToken::new();
        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.proto = Some(Box::new(MockFerrumProto::new(2048)));
        let result = FerrumServer::handle_client(&mut client, cancel_token, 50).await;
        assert_eq!(result.is_err(), true);
        let err_msg = result.unwrap_err().to_string();
        assert_eq!(err_msg.starts_with("deadline"), true);
    }

    #[tokio::test]
    async fn test_server_handle_client_read_error() {
        //test h2

        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                Err(anyhow!("fake error"))
            }
        }

        struct MockFerrumProto {
            real: FerrumProtoDefault,
        }
        impl MockFerrumProto {
            pub fn new(buf_size: usize) -> Self {
                MockFerrumProto {
                    real: FerrumProtoDefault::new(buf_size),
                }
            }
        }
        impl FerrumProto for MockFerrumProto {
            fn write(&mut self, buf: &[u8]) {
                self.real.write(buf);
            }
            fn decode_frame(&mut self) -> Result<FerrumFrame> {
                return self.real.decode_frame();
            }
            fn encode_frame_str(&self, _val: &str) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_str(_val)
            }
            fn encode_frame_bytes(&self, _val: &[u8]) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_bytes(_val)
            }
        }

        let mut client = create_client();
        let cancel_token = CancellationToken::new();
        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.proto = Some(Box::new(MockFerrumProto::new(2048)));
        let result = FerrumServer::handle_client(&mut client, cancel_token, 50).await;
        assert_eq!(result.is_err(), true);
        let err_msg = result.unwrap_err().to_string();
        assert_eq!(err_msg.starts_with("stream read error"), true);
    }

    #[tokio::test]
    async fn test_server_handle_client_read_byte_frame() {
        //test h3

        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                tokio::time::sleep(Duration::from_millis(1000)).await;
                Ok(Some(0))
            }
        }

        struct MockFerrumProto {
            real: FerrumProtoDefault,
        }
        impl MockFerrumProto {
            pub fn new(buf_size: usize) -> Self {
                MockFerrumProto {
                    real: FerrumProtoDefault::new(buf_size),
                }
            }
        }
        impl FerrumProto for MockFerrumProto {
            fn write(&mut self, buf: &[u8]) {
                self.real.write(buf);
            }
            fn decode_frame(&mut self) -> Result<FerrumFrame> {
                return self.real.decode_frame();
            }
            fn encode_frame_str(&self, _val: &str) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_str(_val)
            }
            fn encode_frame_bytes(&self, _val: &[u8]) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_bytes(_val)
            }
        }

        let mut client = create_client();
        let cancel_token = CancellationToken::new();
        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.proto = Some(Box::new(MockFerrumProto::new(2048)));

        client
            .proto
            .as_mut()
            .unwrap()
            .write(&[FERRUM_FRAME_BYTES_TYPE]);
        client.proto.as_mut().unwrap().write(&5u16.to_be_bytes());
        client.proto.as_mut().unwrap().write(b"ferrum_open:");

        let result = FerrumServer::handle_client(&mut client, cancel_token, 50).await;
        assert_eq!(result.is_err(), true);
        let err_msg = result.unwrap_err().to_string();
        assert_eq!(err_msg.starts_with("protocol error"), true);
    }

    #[tokio::test]
    async fn test_server_handle_client_read_hello_frame_error() {
        //test h4

        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                tokio::time::sleep(Duration::from_millis(1000)).await;
                Ok(Some(0))
            }
        }

        struct MockFerrumProto {
            real: FerrumProtoDefault,
        }
        impl MockFerrumProto {
            pub fn new(buf_size: usize) -> Self {
                MockFerrumProto {
                    real: FerrumProtoDefault::new(buf_size),
                }
            }
        }
        impl FerrumProto for MockFerrumProto {
            fn write(&mut self, buf: &[u8]) {
                self.real.write(buf);
            }
            fn decode_frame(&mut self) -> Result<FerrumFrame> {
                return self.real.decode_frame();
            }
            fn encode_frame_str(&self, _val: &str) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_str(_val)
            }
            fn encode_frame_bytes(&self, _val: &[u8]) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_bytes(_val)
            }
        }

        let mut client = create_client();
        let cancel_token = CancellationToken::new();
        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.proto = Some(Box::new(MockFerrumProto::new(2048)));

        client
            .proto
            .as_mut()
            .unwrap()
            .write(&[FERRUM_FRAME_STR_TYPE]);
        client.proto.as_mut().unwrap().write(&8u16.to_be_bytes());
        client.proto.as_mut().unwrap().write(b"heelll0o");

        let result = FerrumServer::handle_client(&mut client, cancel_token, 50).await;
        assert_eq!(result.is_err(), true);
        let err_msg = result.unwrap_err().to_string();
        assert_eq!(err_msg.starts_with("protocol error"), true);
    }

    #[tokio::test]
    async fn test_server_handle_client_redis_connect_error() {
        //test r1

        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                tokio::time::sleep(Duration::from_millis(1000)).await;
                Ok(Some(0))
            }
        }

        struct MockFerrumProto {
            real: FerrumProtoDefault,
        }
        impl MockFerrumProto {
            pub fn new(buf_size: usize) -> Self {
                MockFerrumProto {
                    real: FerrumProtoDefault::new(buf_size),
                }
            }
        }
        impl FerrumProto for MockFerrumProto {
            fn write(&mut self, buf: &[u8]) {
                self.real.write(buf);
            }
            fn decode_frame(&mut self) -> Result<FerrumFrame> {
                return self.real.decode_frame();
            }
            fn encode_frame_str(&self, _val: &str) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_str(_val)
            }
            fn encode_frame_bytes(&self, _val: &[u8]) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_bytes(_val)
            }
        }

        let mut client = create_client();
        let cancel_token = CancellationToken::new();
        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.proto = Some(Box::new(MockFerrumProto::new(2048)));
        client.redis_host = "127.0.0.1:5555".to_string();

        client
            .proto
            .as_mut()
            .unwrap()
            .write(&[FERRUM_FRAME_STR_TYPE]);
        client.proto.as_mut().unwrap().write(&5u16.to_be_bytes());
        client.proto.as_mut().unwrap().write(b"hello");

        let result = FerrumServer::handle_client(&mut client, cancel_token, 50).await;
        assert_eq!(result.is_err(), true);
        let err_msg = result.unwrap_err().to_string();
        assert_eq!(err_msg.starts_with("Connection refused"), true);
    }

    #[tokio::test]
    async fn test_server_handle_client_redis_ok_error() {
        //test r3

        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                tokio::time::sleep(Duration::from_millis(1000)).await;
                Ok(Some(0))
            }
        }
        struct MockSendStream {
            buf: Arc<Mutex<Vec<u8>>>,
        }

        #[async_trait]
        impl FerrumWriteStream for MockSendStream {
            async fn write_ext(&mut self, buf: &mut [u8]) -> Result<(), anyhow::Error> {
                self.buf.lock().unwrap().extend_from_slice(buf);
                Ok(())
            }
        }

        struct MockFerrumProto {
            real: FerrumProtoDefault,
        }
        impl MockFerrumProto {
            pub fn new(buf_size: usize) -> Self {
                MockFerrumProto {
                    real: FerrumProtoDefault::new(buf_size),
                }
            }
        }
        impl FerrumProto for MockFerrumProto {
            fn write(&mut self, buf: &[u8]) {
                self.real.write(buf);
            }
            fn decode_frame(&mut self) -> Result<FerrumFrame> {
                return self.real.decode_frame();
            }
            fn encode_frame_str(&self, _val: &str) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_str(_val)
            }
            fn encode_frame_bytes(&self, _val: &[u8]) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_bytes(_val)
            }
        }

        let mut client = create_client();
        let cancel_token = CancellationToken::new();
        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.proto = Some(Box::new(MockFerrumProto::new(2048)));
        client.redis_host = "127.0.0.1:6379".to_string();
        let rc = Arc::new(Mutex::new(Vec::<u8>::new()));
        client.write_stream = Some(Box::new(MockSendStream { buf: rc.clone() }));

        client
            .proto
            .as_mut()
            .unwrap()
            .write(&[FERRUM_FRAME_STR_TYPE]);
        client.proto.as_mut().unwrap().write(&5u16.to_be_bytes());
        client.proto.as_mut().unwrap().write(b"hello");

        let write_stream2 = rc.clone();
        let task = tokio::spawn(async move {
            let mut redis = RedisClient::new("127.0.0.1:6379", None, None);
            let _res = redis.connect().await.map_err(|_err| {
                panic!("redis cannot connect");
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            let msg = String::from_utf8(write_stream2.lock().unwrap().to_vec()).unwrap();
            let items: Vec<&str> = msg.split(' ').collect();
            let tunnel_id = items[1];
            let _res = redis
                .publish(
                    format!("/tunnel/authentication/{}", tunnel_id).as_str(),
                    "ok2:",
                )
                .await
                .map_err(|_err| {
                    panic!("redis publish failed");
                });
        });

        let result = FerrumServer::handle_client(&mut client, cancel_token, 50).await;
        let _ = tokio::join!(task);
        assert_eq!(result.is_err(), true);
        let err_msg = result.unwrap_err().to_string();
        assert_eq!(err_msg.starts_with("could not authenticate"), true);
    }

    #[tokio::test]
    async fn test_server_handle_client_ferrum_tunnel_confirmed() {
        //test r4

        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                tokio::time::sleep(Duration::from_millis(1000)).await;
                Ok(Some(0))
            }
        }
        struct MockSendStream {
            buf: Arc<Mutex<Vec<u8>>>,
            count: i32,
        }

        #[async_trait]
        impl FerrumWriteStream for MockSendStream {
            async fn write_ext(&mut self, buf: &mut [u8]) -> Result<(), anyhow::Error> {
                self.buf.lock().unwrap().extend_from_slice(buf);
                self.count += 1;
                if self.count > 1 {
                    Err(anyhow!("stop here"))
                } else {
                    Ok(())
                }
            }
        }

        struct MockFerrumProto {
            real: FerrumProtoDefault,
        }
        impl MockFerrumProto {
            pub fn new(buf_size: usize) -> Self {
                MockFerrumProto {
                    real: FerrumProtoDefault::new(buf_size),
                }
            }
        }
        impl FerrumProto for MockFerrumProto {
            fn write(&mut self, buf: &[u8]) {
                self.real.write(buf);
            }
            fn decode_frame(&mut self) -> Result<FerrumFrame> {
                return self.real.decode_frame();
            }
            fn encode_frame_str(&self, _val: &str) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_str(_val)
            }
            fn encode_frame_bytes(&self, _val: &[u8]) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_bytes(_val)
            }
        }

        struct MockTun {
            sended: bool,
        }
        #[async_trait]
        impl FerrumTun for MockTun {
            fn get_name(&self) -> &str {
                "mocktun"
            }
            async fn read(&mut self) -> Result<FerrumTunFrame> {
                if self.sended {
                    tokio::time::sleep(Duration::from_millis(10000000)).await;
                }
                let mut by = BytesMut::new();
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                self.sended = true;
                Ok(FerrumTunFrame { data: by })
            }
            async fn write(&mut self, _buf: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        let mut client = create_client();
        let cancel_token = CancellationToken::new();
        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.proto = Some(Box::new(MockFerrumProto::new(2048)));
        client.redis_host = "127.0.0.1:6379".to_string();
        let arc = Arc::new(Mutex::new(Vec::<u8>::new()));
        client.write_stream = Some(Box::new(MockSendStream {
            count: 0,
            buf: arc.clone(),
        }));
        client.tun = Some(Box::new(MockTun { sended: false }));
        client
            .proto
            .as_mut()
            .unwrap()
            .write(&[FERRUM_FRAME_STR_TYPE]);
        client.proto.as_mut().unwrap().write(&5u16.to_be_bytes());
        client.proto.as_mut().unwrap().write(b"hello");

        let write_stream2 = arc.clone();
        let task = tokio::spawn(async move {
            let mut redis = RedisClient::new("127.0.0.1:6379", None, None);
            let _res = redis.connect().await.map_err(|_err| {
                panic!("redis cannot connect");
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            let msg = String::from_utf8(write_stream2.lock().unwrap().to_vec()).unwrap();
            let items: Vec<&str> = msg.split(' ').collect();
            let tunnel_id = items[1];
            write_stream2.lock().unwrap().clear();
            let _res = redis
                .publish(
                    format!("/tunnel/authentication/{}", tunnel_id).as_str(),
                    "ok:",
                )
                .await
                .map_err(|_err| {
                    panic!("redis publish failed");
                });
        });

        let result = FerrumServer::handle_client(&mut client, cancel_token, 50).await;
        let _ = tokio::join!(task);
        assert_eq!(result.is_err(), true);
        let err_msg = result.unwrap_err().to_string();
        let msg = String::from_utf8(arc.lock().unwrap().to_vec()[3..].to_vec()).unwrap();
        assert_eq!(msg, "ferrum_tunnel_confirmed:");
        assert_eq!(err_msg.starts_with("stop here"), true);
    }
}
