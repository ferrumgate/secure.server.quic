use std::{net::SocketAddr, path::PathBuf};

pub struct FerrumClientConfig {
    pub host: String,
    pub host_port: String,
    pub ip: SocketAddr,
    pub ca: Option<PathBuf>,
    pub keylog: bool,
    pub rebind: bool,
    pub insecure: bool,
    pub stdinout: bool,
    pub loglevel: String,
    pub idle_timeout: u32,
    pub connect_timeout: u64,
}
