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

pub async fn run(action: SystemAction, format: &Format) -> Result<()> {
    match action {
        SystemAction::Doctor => {
            let config_dir = config::config_dir();
            let cfg = config::load_config();

            let market = contract::get_market_status().await;
            let wallet = config::get_private_key()
                .ok()
                .and_then(|k| {
                    // Try to get wallet info synchronously is tricky, check key validity
                    Some(k)
                });

            let info = serde_json::json!({
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
            });
            output::print_success(format, "system.doctor", &info);
        }
        SystemAction::Whoami => {
            let key = config::get_private_key()?;
            let wallet = contract::get_wallet_info(&key).await?;
            output::print_success(format, "system.whoami", &wallet);
        }
        SystemAction::Keygen { force } => {
            use crate::crypto;
            if crypto::delivery_keys_exist() && !force {
                anyhow::bail!(
                    "Keys already exist at ~/.pora/keys/. Use --force to regenerate."
                );
            }
            let (priv_path, pub_path) = crypto::generate_x25519_keypair()?;
            let pubkey_hex = std::fs::read_to_string(&pub_path)?;
            let info = serde_json::json!({
                "private_key": priv_path.to_string_lossy(),
                "public_key": pub_path.to_string_lossy(),
                "pubkey_hex": pubkey_hex.trim(),
                "message": "X25519 delivery keypair generated. BACK UP ~/.pora/keys/delivery.key — it is required to decrypt audit results."
            });
            output::print_success(format, "system.keygen", &info);
        }
    }
    Ok(())
}
