#[cfg(test)]
mod tests {

    use ferrum::client::FerrumClient;
    use ferrum::client::FerrumClientConfig;

    use ferrum::server::FerrumServer;
    use ferrum::server::FerrumServerConfig;
    use tokio::time::Duration;
    use tokio_util::sync::CancellationToken;
    fn create_client_config(ip: &str) -> FerrumClientConfig {
        FerrumClientConfig {
            ca: None,
            host: "localhost".to_string(),
            host_port: ip.to_string(),
            ip: ip.parse().unwrap(),
            keylog: false,
            rebind: false,
            insecure: true,
            stdinout: false,
            loglevel: "debug".to_string(),
            connect_timeout: 100,
            idle_timeout: 15000,
        }
    }

    fn create_server_config(ip: &str) -> FerrumServerConfig {
        FerrumServerConfig {
            listen: ip.parse().unwrap(),
            ip: ip.to_string(),
            stdinout: true,
            loglevel: "debug".to_string(),
            keylog: false,
            key: None,
            cert: None,
            connect_timeout: 3000,
            idle_timeout: 15000,
            gateway_id: "gateway_test_id".to_string(),
            redis_host: "localhost:6379".to_string(),
            redis_pass: None,
            redis_user: None,
            ratelimit: 60,
            ratelimit_window: 60000,
        }
    }

    /* fn create_server_cert_chain(options: &FerrumServerConfig) -> FerrumServerCertChain {
        FerrumServer::create_server_cert_chain(options).unwrap()
    } */
    #[tokio::test]
    async fn test_ferrum_client_connect_timeout() {
        let config = create_client_config("127.0.0.1:9876");
        let roots = FerrumClient::create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, roots);
        let result = client
            .connect()
            .await
            .map_err(|e| eprintln!("error occured {}", e));

        assert_eq!(result.is_err(), true);
    }

    #[tokio::test]
    async fn test_ferrum_client_connect_then_cancel_server_listening() {
        let mut config_server = create_server_config("127.0.0.1:8443");
        config_server.connect_timeout = 3000;

        let server_crt = FerrumServer::create_server_cert_chain(&config_server).unwrap();
        let mut server = FerrumServer::new(config_server, server_crt).unwrap();
        let token = CancellationToken::new();
        let token_clone = token.clone();

        //start server
        let server_task = tokio::spawn(async move {
            server.listen(token_clone).await;
            server.close();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await; //wait a litte
        let mut config = create_client_config("127.0.0.1:8443");
        config.connect_timeout = 3000;

        let roots = FerrumClient::create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, roots);
        //define a anonymous struct

        //start client

        let result = client.connect().await;
        assert_eq!(result.is_ok(), true);
        client.close();

        token.cancel();
        let _ = tokio::join!(server_task);
    }

    #[tokio::test]
    async fn test_ferrum_client_write_to_server() {
        let mut config_server = create_server_config("127.0.0.1:8444");
        config_server.connect_timeout = 3000;

        let server_crt = FerrumServer::create_server_cert_chain(&config_server).unwrap();
        let mut server = FerrumServer::new(config_server, server_crt).unwrap();
        let token = CancellationToken::new();
        let token_clone = token.clone();

        //start server
        let server_task = tokio::spawn(async move {
            server.listen(token_clone).await;
            server.close();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await; //wait a litte
        let mut config = create_client_config("127.0.0.1:8444");
        config.connect_timeout = 3000;

        let roots = FerrumClient::create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, roots);

        //start client

        client.connect().await.unwrap();
        //let _ = client send.write_all(b"ops").await;
        //let _ = recv.read(a.data.as_mut()).await;
        client.close();

        token.cancel();
        let _ = tokio::join!(server_task);
    }
}
