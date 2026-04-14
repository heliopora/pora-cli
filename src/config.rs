use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DEFAULT_RPC: &str = "https://testnet.sapphire.oasis.io";
const DEFAULT_CONTRACT: &str = "0x2B057b903850858A00aCeFFdE12bdb604e781573";

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub rpc_url: String,
    pub contract: String,
    pub private_key: Option<String>,
    pub gateway_url: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rpc_url: DEFAULT_RPC.to_string(),
            contract: DEFAULT_CONTRACT.to_string(),
            private_key: None,
            gateway_url: None,
        }
    }
}

pub fn config_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join(".pora")
}

pub fn load_config() -> Config {
    let path = config_dir().join("config.toml");
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(config) = toml::from_str(&content) {
                return config;
            }
        }
    }

    // Fall back to env vars + defaults
    Config {
        rpc_url: std::env::var("PORA_RPC_URL").unwrap_or_else(|_| DEFAULT_RPC.to_string()),
        contract: std::env::var("PORA_CONTRACT").unwrap_or_else(|_| DEFAULT_CONTRACT.to_string()),
        private_key: std::env::var("PORA_PRIVATE_KEY").ok(),
        gateway_url: std::env::var("PORA_GATEWAY_URL").ok(),
    }
}

pub fn get_private_key() -> Result<String> {
    // Priority: env var > config file
    if let Ok(key) = std::env::var("PORA_PRIVATE_KEY") {
        return Ok(key);
    }
    let config = load_config();
    config.private_key.context(
        "No private key configured. Set PORA_PRIVATE_KEY or add it to ~/.pora/config.toml"
    )
}
