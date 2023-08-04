use anyhow::{Ok, Result};

use redis::AsyncCommands;

use std::time::Duration;

use tokio_stream::StreamExt;

#[allow(unused)]
pub struct RedisClient {
    host: String,
    username: Option<String>,
    password: Option<String>,
    client: Option<redis::Client>,
    connection: Option<redis::aio::Connection>,
}

#[allow(unused)]
impl RedisClient {
    pub fn new(host: &str, username: Option<String>, password: Option<String>) -> Self {
        RedisClient {
            host: host.to_string(),
            username: username,
            password: password,
            client: None,
            connection: None,
        }
    }
    async fn internal_connect(self: &mut Self) -> Result<(redis::Client, redis::aio::Connection)> {
        let mut url = format!("redis://{}/", self.host.clone());
        if self.username.is_some() {
            url = format!(
                "redis://{}:{}@{}/",
                self.username.as_ref().unwrap().clone(),
                self.password.as_ref().unwrap().clone(),
                self.host.clone(),
            );
        }

        let client = redis::Client::open(url)?;
        let connection = client.get_async_connection().await?;
        Ok((client, connection))
    }
    async fn get_connection(self: &mut Self) -> Result<redis::aio::Connection> {
        Ok(self.client.as_mut().unwrap().get_async_connection().await?)
    }
    pub async fn connect(self: &mut Self) -> Result<&Self> {
        let (client, connection) = self.internal_connect().await?;
        self.client = Some(client);
        self.connection = Some(connection);
        Ok(self)
    }
    pub async fn subscribe(self: &mut Self, channel: &str, timeout: Duration) -> Result<String> {
        let (client, mut connection) = self.internal_connect().await?;
        self.client = Some(client);

        let mut pubsub = connection.into_pubsub();

        tokio::time::timeout(timeout, pubsub.subscribe(channel)).await?;

        let mut pubsub_stream = pubsub.on_message();
        let pubsub_msg = tokio::time::timeout(timeout, pubsub_stream.next()).await?;

        if let None = pubsub_msg {
            return Ok("".to_string());
        }

        Ok(pubsub_msg.unwrap().get_payload()?)
    }
    pub async fn publish(self: &mut Self, channel: &str, message: &str) -> Result<()> {
        let mut publish_conn = self.connection.as_mut().unwrap();

        publish_conn.publish(channel, message).await?;

        Ok(())
    }

    pub async fn execute(
        self: &mut Self,
        tunnel_id: &str,
        client_ip: &str,
        gateway_id: &str,
        timeout: u32,
    ) -> Result<()> {
        //int32_t result= redis_execute(pamh,redis,"hset /tunnel/id/%s clientIp %s id %s gatewayId %s type %s",tunnel_id,client_ip,tunnel_id,gateway_id,"ssh");
        // result = redis_execute(pamh, redis, "pexpire /tunnel/id/%s 300000", tunnel_id);
        let mut connection = self.connection.as_mut().unwrap();
        let _ = redis::pipe()
            .atomic()
            .cmd("hset")
            .arg(format!("/tunnel/id/{}", tunnel_id))
            .arg("clientIp")
            .arg(client_ip)
            .arg("id")
            .arg(tunnel_id)
            .arg("gatewayId")
            .arg(gateway_id)
            .arg("type")
            .arg("quic")
            .ignore()
            .cmd("pexpire")
            .arg(format!("/tunnel/id/{}", tunnel_id))
            .arg(timeout.to_string())
            .ignore()
            .query_async(connection)
            .await?;
        Ok(())
    }
}

#[allow(unused)]
#[cfg(test)]
mod tests {

    use std::{
        fs::create_dir,
        net::ToSocketAddrs,
        ops::DerefMut,
        sync::Arc,
        time::{Duration, Instant},
    };

    use rand::Rng;
    use tokio::sync::futures;

    use super::*;

    #[tokio::test]
    async fn test_redis_connect() {
        let mut redis = RedisClient::new("0.0.0.0:6379", None, None);
        let result = redis.connect().await;
        assert_eq!(result.is_ok(), true);
    }
    #[tokio::test]
    async fn test_redis_connect_fails() {
        let mut redis = RedisClient::new("0.0.0.0:6380", None, None);
        let result = redis.connect().await;
        assert_eq!(result.is_err(), true);
    }
    #[tokio::test]
    async fn test_redis_subscribe_timeout() {
        let mut redis = RedisClient::new("0.0.0.0:6379", None, None);
        let channel = format!("hello {}", Instant::now().elapsed().as_nanos());
        let result = redis
            .subscribe(channel.as_str(), std::time::Duration::from_millis(5))
            .await;
        assert_eq!(result.is_err(), true);
    }

    #[tokio::test]
    async fn test_redis_subscribe_publish() {
        let mut response = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let mut res2 = response.clone();

        let task1 = tokio::spawn(async move {
            let mut redis = RedisClient::new("0.0.0.0:6379", None, None);
            let result = redis.subscribe("hello34", Duration::from_millis(400)).await;
            if result.is_err() {
                return;
            }

            res2.lock().unwrap().push_str(result.unwrap().as_str());
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut redis2 = RedisClient::new("0.0.0.0:6379", None, None);
        let res = redis2.connect().await;
        if let Err(err) = res {
            return;
        }

        let res = redis2.publish("hello34", "world").await;
        if let Err(res) = res {
            return;
        }

        tokio::join!(task1);

        assert_eq!(response.lock().unwrap().as_str(), "world");
    }

    #[tokio::test]
    async fn test_redis_multi_publish_connection() {
        let mut redis2 = RedisClient::new("0.0.0.0:6379", None, None);
        let res = redis2.connect().await;
        if let Err(err) = res {
            return;
        }
        for i in 1..1000 {
            let res = redis2.publish("hello", "world").await;
            if let Err(res) = res {
                return;
            }
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    #[tokio::test]
    async fn test_redis_multi_publish_connection2() {
        for i in 1..1000 {
            let mut redis2 = RedisClient::new("0.0.0.0:6379", None, None);
            let res = redis2.connect().await;
            if let Err(err) = res {
                return;
            }
            let res = redis2.publish("hello", "world").await;
            if let Err(res) = res {
                return;
            }
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn test_redis_multi_publish_connection3() {
        let mut set = tokio::task::JoinSet::new();
        let mut rng = rand::thread_rng();

        let tasks = (1..100).for_each(|i| {
            let n1 = rng.gen_range(0..1000);
            let n2 = rng.gen_range(0..1000);
            set.spawn(async move {
                let mut redis2 = RedisClient::new("0.0.0.0:6379", None, None);
                let res = redis2.connect().await;
                if let Err(err) = res {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(n1)).await;
                let res = redis2.publish("hello2", "world").await;
                if let Err(res) = res {
                    return;
                }
                eprintln!("starting task {}", i);

                tokio::time::sleep(Duration::from_millis(n2)).await;
            });
        });
        while let Some(item) = set.join_next().await {}

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    #[tokio::test]
    async fn test_redis_open_5000k_connection() {
        // if fails check ulimit -Sn
        // for increment set on bash ulimit -Sn 10000
        let mut set = tokio::task::JoinSet::new();
        let mut rng = rand::thread_rng();
        struct Atomic {
            val: i32,
        }
        let counter = Arc::new(std::sync::Mutex::new(Atomic { val: 0 }));
        let tasks = (1..5000).for_each(|i| {
            let n1 = rng.gen_range(0..1000);
            let n2 = rng.gen_range(0..1000);
            let counter = counter.clone();
            set.spawn(async move {
                let mut redis2 = RedisClient::new("0.0.0.0:6379", None, None);
                let res = redis2.connect().await;
                if let Err(err) = res {
                    eprintln!("connection open failed {}", err);
                    let mut x = counter.lock().unwrap();
                    x.val = x.val + 1;
                    return;
                }
                let res = redis2.publish("hello2", "world").await;
                if let Err(res) = res {
                    eprintln!("publish failed");
                    return;
                }

                tokio::time::sleep(Duration::from_millis(5000)).await;
            });
        });
        while let Some(item) = set.join_next().await {}

        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(counter.lock().unwrap().val, 0);
    }

    #[tokio::test]
    async fn test_redis_execute() {
        let mut redis2 = RedisClient::new("0.0.0.0:6379", None, None);
        let res = redis2.connect().await;
        assert_eq!(res.is_err(), false);

        let res = redis2
            .execute("tunnelid", "clientip", "gatewayid", 10000)
            .await;
        assert_eq!(res.is_err(), false);
    }
}
