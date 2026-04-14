use anyhow::Result;
use clap::Subcommand;

use crate::config;
use crate::contract;
use crate::output::{self, Format};

#[derive(Subcommand)]
pub enum SystemAction {
    /// Check config, connectivity, wallet balance, registration
    Doctor,
    /// Show wallet address, network, balance
    Whoami,
    /// Generate X25519 delivery keypair for encrypted audit results
    Keygen {
        /// Overwrite existing keys
        #[arg(long)]
        force: bool,
    },
}

// checks: none (reads config and network state)
// effects: none (read-only)
// returns: structured health check data
pub async fn execute_doctor() -> Result<serde_json::Value> {
    let config_dir = config::config_dir();
    let cfg = config::load_config();

    let market = contract::get_market_status().await;
    let wallet = config::get_private_key().ok();

    Ok(serde_json::json!({
        "checks": {
            "config_dir": {
                "path": config_dir.to_string_lossy(),
                "exists": config_dir.exists(),
            },
            "wallet": {
                "status": if wallet.is_some() { "configured" } else { "missing" },
                "action": if wallet.is_some() { "none" } else { "Set PORA_PRIVATE_KEY env var" },
            },
            "network": {
                "rpc": cfg.rpc_url,
                "contract": cfg.contract,
                "status": if market.is_ok() { "connected" } else { "unreachable" },
                "bounties": market.as_ref().map(|m| m.bounty_count).unwrap_or(0),
                "audits": market.as_ref().map(|m| m.audit_count).unwrap_or(0),
            },
            "performer_config": {
                "status": if config_dir.join("performer.json").exists() { "configured" } else { "not_configured" },
            },
            "keys": {
                "status": if crate::crypto::delivery_keys_exist() { "ok" } else { "missing" },
                "path": config::keys_dir().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                "action": if crate::crypto::delivery_keys_exist() { "none" } else { "Run 'pora system keygen' or keys will auto-generate on first submit" },
            },
        }
    }))
}

// checks: private key configured
// effects: none (read-only RPC call)
// returns: wallet address, network, balance
pub async fn execute_whoami() -> Result<serde_json::Value> {
    let key = config::get_private_key()?;
    let wallet = contract::get_wallet_info(&key).await?;
    Ok(serde_json::to_value(&wallet)?)
}

// checks: keys don't exist (unless force)
// effects: generates X25519 keypair to ~/.pora/keys/
// returns: key paths and public key hex
pub fn execute_keygen(force: bool) -> Result<serde_json::Value> {
    use crate::crypto;
    if crypto::delivery_keys_exist() && !force {
        anyhow::bail!(
            "Keys already exist at ~/.pora/keys/. Use --force to regenerate."
        );
    }
    // WHY: delivery keys decrypt audit results — losing them means losing access to past results.
    //      backup before overwrite so the user can recover if needed.
    if force && crypto::delivery_keys_exist() {
        let keys_dir = dirs::home_dir().unwrap().join(".pora/keys");
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for name in &["delivery.key", "delivery.pub"] {
            let src = keys_dir.join(name);
            if src.exists() {
                let backup = keys_dir.join(format!("{}.bak.{}", name, timestamp));
                std::fs::copy(&src, &backup)?;
            }
        }
    }
    let (priv_path, pub_path) = crypto::generate_x25519_keypair()?;
    let pubkey_hex = std::fs::read_to_string(&pub_path)?;
    Ok(serde_json::json!({
        "private_key": priv_path.to_string_lossy(),
        "public_key": pub_path.to_string_lossy(),
        "pubkey_hex": pubkey_hex.trim(),
        "message": "X25519 delivery keypair generated. BACK UP ~/.pora/keys/delivery.key — it is required to decrypt audit results."
    }))
}

pub async fn run(action: SystemAction, format: &Format) -> Result<()> {
    match action {
        SystemAction::Doctor => {
            let data = execute_doctor().await?;
            output::print_success(format, "system.doctor", &data);
        }
        SystemAction::Whoami => {
            let data = execute_whoami().await?;
            output::print_success(format, "system.whoami", &data);
        }
        SystemAction::Keygen { force } => {
            let data = execute_keygen(force)?;
            output::print_success(format, "system.keygen", &data);
        }
    }
    Ok(())
}
