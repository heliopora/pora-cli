use anyhow::{Context, Result};
use clap::Subcommand;
use serde_json::json;

use crate::abi;
use crate::config;
use crate::output::{self, Format};

#[derive(Subcommand)]
pub enum PerformerAction {
    /// Initialize performer config (wallet, provider, API key)
    Init {
        /// LLM provider: anthropic, openai, openrouter
        #[arg(long, default_value = "anthropic")]
        provider: String,
        /// Auto-detect Claude Code OAuth token
        #[arg(long)]
        use_claude_login: bool,
    },
    /// Monitor on-chain events for this performer (read-only, NDJSON stream)
    Start {
        /// Poll interval in seconds
        #[arg(long, default_value = "5")]
        interval: u64,
        /// Snapshot current state then exit
        #[arg(long)]
        once: bool,
    },
    /// Show earnings, reputation, and active jobs
    Status,
}

/// Monitor on-chain events for this performer (read-only, per AD-2).
// WHY: this is a read-only observer, NOT a TEE control plane.
//      The TEE (ROFL container) runs autonomously. This command provides visibility.
async fn execute_start(interval: u64, once: bool) -> Result<()> {
    let cfg = config::load_config();
    let rpc = crate::rpc::RpcClient::new(&cfg.rpc_url);

    // Load performer address
    let performer_address = if let Ok(key) = config::get_private_key() {
        crate::crypto::private_key_to_address(&key)?
    } else {
        // Try loading from ~/.pora/performer.json
        load_performer_address()
            .context("No performer key found. Set PORA_PRIVATE_KEY or run 'pora performer init'")?
    };

    // Verify performer registration
    let calldata = abi::encode_get_performer(&performer_address);
    match rpc.eth_call(&cfg.contract, &calldata).await {
        Ok(result) => {
            if abi::is_zero_result(&result) {
                anyhow::bail!(
                    "Address {} is not registered as a performer",
                    performer_address
                );
            }
        }
        Err(e) => {
            // WHY: don't fail hard — the contract may not have getPerformer. Warn and continue.
            output::ndjson_event(json!({
                "event": "warning",
                "message": format!("Could not verify registration: {}", e),
            }));
        }
    }

    let addr_clean = performer_address.trim_start_matches("0x").to_lowercase();
    let performer_topic = format!("0x000000000000000000000000{}", addr_clean);

    const ONCE_LOOKBACK: u64 = 50_000;
    let current = rpc.eth_block_number().await?;
    let mut from_block = if once { current.saturating_sub(ONCE_LOOKBACK) } else { current };
    let sleep_dur = tokio::time::Duration::from_secs(interval);
    let mut heartbeat_counter = 0u64;

    loop {
        let current_block = rpc.eth_block_number().await.unwrap_or(from_block);

        if current_block >= from_block {
            let from_hex = format!("0x{:x}", from_block);
            let to_hex = format!("0x{:x}", current_block);

            // AuditPayoutClaimed — performer is topic[2], filter directly
            rpc.fetch_and_emit_logs(
                &cfg.contract,
                &[Some(abi::audit_payout_claimed_topic()), None, Some(&performer_topic)],
                &from_hex, &to_hex, "payout.claimed",
            ).await;

            // Events without performer index — emit all, client correlates
            for (topic0, event_name) in [
                (abi::audit_submitted_topic(), "audit.submitted"),
                (abi::audit_result_submitted_topic(), "audit.result_submitted"),
                (abi::audit_delivery_recorded_topic(), "audit.delivery_recorded"),
            ] {
                rpc.fetch_and_emit_logs(
                    &cfg.contract, &[Some(topic0)],
                    &from_hex, &to_hex, event_name,
                ).await;
            }

            from_block = current_block + 1;
        }

        heartbeat_counter += 1;
        output::ndjson_event(json!({
            "event": "heartbeat",
            "block": current_block,
            "performer": performer_address,
            "tick": heartbeat_counter,
        }));

        if once { return Ok(()); }

        tokio::select! {
            _ = tokio::time::sleep(sleep_dur) => {},
            _ = tokio::signal::ctrl_c() => { return Ok(()); }
        }
    }
}

fn load_performer_address() -> Option<String> {
    let path = config::config_dir().join("performer.json");
    let content = std::fs::read_to_string(path).ok()?;
    let val: serde_json::Value = serde_json::from_str(&content).ok()?;
    val["address"].as_str().map(|s| s.to_string())
}

pub async fn run(action: PerformerAction, format: &Format) -> Result<()> {
    match action {
        PerformerAction::Init { provider, use_claude_login } => {
            let mut api_key_source = "manual".to_string();

            if use_claude_login {
                // Auto-detect Claude Code OAuth token
                if let Some(home) = dirs::home_dir() {
                    let creds_path = home.join(".claude").join(".credentials.json");
                    if creds_path.exists() {
                        let creds: serde_json::Value = serde_json::from_str(
                            &std::fs::read_to_string(&creds_path)?
                        )?;
                        if let Some(oauth) = creds.get("claudeAiOauth") {
                            if let Some(token) = oauth.get("accessToken").and_then(|t| t.as_str()) {
                                let sub_type = oauth.get("subscriptionType")
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("unknown");
                                api_key_source = format!("claude-oauth ({})", sub_type);

                                let info = serde_json::json!({
                                    "provider": provider,
                                    "api_key_source": api_key_source,
                                    "token_prefix": &token[..20],
                                    "subscription": sub_type,
                                    "message": "Claude Code OAuth token detected. No additional API costs."
                                });
                                output::print_success(format, "performer.init", &info);
                                return Ok(());
                            }
                        }
                    }
                }
                anyhow::bail!("Claude Code credentials not found at ~/.claude/.credentials.json. Run 'claude' and log in first.");
            }

            let info = serde_json::json!({
                "provider": provider,
                "api_key_source": api_key_source,
                "status": "not_implemented",
                "message": "Set ANTHROPIC_API_KEY or use --use-claude-login"
            });
            output::print_success(format, "performer.init", &info);
        }
        PerformerAction::Start { interval, once } => {
            execute_start(interval, once).await?;
        }
        PerformerAction::Status => {
            let info = serde_json::json!({
                "status": "not_implemented",
                "message": "Will show: earnings, reputation score, active jobs, API spend"
            });
            output::print_success(format, "performer.status", &info);
        }
    }
    Ok(())
}
