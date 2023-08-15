use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone)]
pub struct FerrumServerConfig {
    pub listen: SocketAddr,
    pub ip: String,
    pub stdinout: bool,
    pub loglevel: String,
    pub keylog: bool,
    pub key: Option<PathBuf>,
    pub cert: Option<PathBuf>,
    pub connect_timeout: u64,
    pub idle_timeout: u32,
    pub gateway_id: String,
    pub redis_host: String,
    pub redis_user: Option<String>,
    pub redis_pass: Option<String>,
    pub ratelimit: i32,
    pub ratelimit_window: i32,
}
