use anyhow::{Context, Result};
use clap::Subcommand;
use serde_json::json;

use crate::abi;
use crate::config;
use crate::output::{self, Format};

/// Resolve performer address from PORA_PRIVATE_KEY or ~/.pora/performer.json.
// checks: at least one source is available
// returns: Ethereum address as hex string
fn resolve_performer_address() -> Result<String> {
    if let Ok(key) = config::get_private_key() {
        crate::crypto::private_key_to_address(&key)
    } else {
        load_performer_address()
            .context("No performer address found. Set PORA_PRIVATE_KEY or run 'pora performer init'")
    }
}

/// Compute configHash = keccak256(app_id + cli + model + image_hash).
// checks: performer.json must exist with provider field
// effects: none
// returns: 32-byte config hash matching the TEE's compute_config_hash()
//
// WHY: this must match exactly what the ROFL worker computes in main.py's
//      compute_config_hash(). Mismatch = confused-deputy rejection.
// SECURITY: encodePacked concatenation — order matters. Must match Solidity/Python.
fn compute_config_hash() -> Result<[u8; 32]> {
    let performer_path = config::config_dir().join("performer.json");
    let content = std::fs::read_to_string(&performer_path)
        .context("performer.json not found. Run 'pora performer init' first")?;
    let performer: serde_json::Value = serde_json::from_str(&content)?;

    // TRUST: these must match the deployed TEE image exactly.
    //        Default values are for local dev only — production MUST set all three.
    let app_id = std::env::var("PORA_ROFL_APP_ID")
        .unwrap_or_else(|_| "rofl1qr98wz5t6q4dcnlmjhkleqkghk240ruv6pjxvgn".to_string());
    let cli = performer.get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("anthropic")
        .to_string();
    let model = std::env::var("PORA_MODEL")
        .unwrap_or_else(|_| "default".to_string());
    let image_hash = std::env::var("PORA_IMAGE_HASH")
        .unwrap_or_else(|_| "dev".to_string());

    if std::env::var("PORA_ROFL_APP_ID").is_err()
        || std::env::var("PORA_MODEL").is_err()
        || std::env::var("PORA_IMAGE_HASH").is_err()
    {
        output::ndjson_event(json!({
            "event": "warning",
            "message": "Using dev defaults for configHash (PORA_ROFL_APP_ID/PORA_MODEL/PORA_IMAGE_HASH not set). TEE will reject in production.",
        }));
    }

    let mut packed = Vec::new();
    packed.extend_from_slice(app_id.as_bytes());
    packed.extend_from_slice(cli.as_bytes());
    packed.extend_from_slice(model.as_bytes());
    packed.extend_from_slice(image_hash.as_bytes());

    Ok(crate::crypto::keccak256(&packed))
}

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
    /// Claim audit payout for a completed audit
    ClaimPayout {
        /// Audit ID to claim payout for
        audit_id: u64,
    },
    /// Release a bounty claim (claim holder or expired)
    ReleaseClaim {
        /// Bounty ID
        bounty_id: u64,
    },
    /// Request a bounty claim (2-step: local requestClaim -> TEE claimBounty)
    Claim {
        /// Bounty ID to claim
        bounty_id: u64,
        /// Poll timeout in seconds (default: 120, max wait for TEE confirmation)
        #[arg(long, default_value = "120")]
        timeout: u64,
    },
}

/// Monitor on-chain events for this performer (read-only, per AD-2).
// WHY: this is a read-only observer, NOT a TEE control plane.
//      The TEE (ROFL container) runs autonomously. This command provides visibility.
async fn execute_start(interval: u64, once: bool) -> Result<()> {
    let cfg = config::load_config();
    let rpc = crate::rpc::RpcClient::new(&cfg.rpc_url);

    let performer_address = resolve_performer_address()?;

    // Verify performer registration
    // WHY: uses registeredPerformers(address) on LetheMarket (public mapping auto-getter),
    //      NOT getPerformer(address) which is a ReputationRegistry function.
    let calldata = abi::encode_is_registered_performer(&performer_address);
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

    // WHY: track total events only for --once exit-code check; continuous mode never bails on zero.
    let mut total_events: usize = 0;

    loop {
        let current_block = rpc.eth_block_number().await.unwrap_or(from_block);

        if current_block >= from_block {
            // AuditPayoutClaimed — performer is topic[2], filter directly
            total_events += rpc.fetch_and_emit_logs(
                &cfg.contract,
                &[Some(abi::audit_payout_claimed_topic()), None, Some(&performer_topic)],
                from_block, current_block, "payout.claimed",
            ).await;

            // Events without performer index — emit all, client correlates
            for (topic0, event_name) in [
                (abi::audit_submitted_topic(), "audit.submitted"),
                (abi::audit_result_submitted_topic(), "audit.result_submitted"),
                (abi::audit_delivery_recorded_topic(), "audit.delivery_recorded"),
            ] {
                total_events += rpc.fetch_and_emit_logs(
                    &cfg.contract, &[Some(topic0)],
                    from_block, current_block, event_name,
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

        if once {
            // WHY: exit non-zero so scripts consuming NDJSON can detect all-fail scenarios.
            //      Zero events means no activity in the lookback window or all RPC calls failed.
            if total_events == 0 {
                anyhow::bail!(
                    "No events found for performer {} in the last {} blocks",
                    performer_address,
                    ONCE_LOOKBACK
                );
            }
            return Ok(());
        }

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

/// Save performer configuration to ~/.pora/performer.json.
// checks: config_dir is writable
// effects: creates ~/.pora/ if needed, writes performer.json
// returns: Ok on success
fn save_performer_config(address: Option<&str>, provider: &str, api_key_source: &str) -> Result<()> {
    let dir = config::config_dir();
    std::fs::create_dir_all(&dir)?;
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let cfg = serde_json::json!({
        "address": address.unwrap_or(""),
        "provider": provider,
        "api_key_source": api_key_source,
        "created_at": created_at,
    });
    std::fs::write(
        dir.join("performer.json"),
        serde_json::to_string_pretty(&cfg)?,
    )?;
    Ok(())
}

/// Show performer earnings, reputation, and registration status.
// checks: performer address available (from PORA_PRIVATE_KEY or performer.json)
// effects: read-only RPC calls (eth_call + eth_getLogs)
// returns: structured JSON with registration, earnings, reputation
pub async fn execute_status() -> Result<serde_json::Value> {
    let cfg = config::load_config();
    let rpc = crate::rpc::RpcClient::new(&cfg.rpc_url);

    let performer_address = resolve_performer_address()?;

    // 1. Registration status: registeredPerformers(address) on LetheMarket
    let reg_calldata = abi::encode_is_registered_performer(&performer_address);
    let registered = match rpc.eth_call(&cfg.contract, &reg_calldata).await {
        Ok(result) => !abi::is_zero_result(&result),
        Err(_) => false,
    };

    // 2. Reputation: getPerformer(address) on ReputationRegistry (if configured)
    let reputation = if let Some(ref registry) = cfg.reputation_registry {
        let rep_calldata = abi::encode_get_reputation(&performer_address);
        match rpc.eth_call(registry, &rep_calldata).await {
            Ok(result) => {
                let data = result.trim_start_matches("0x");
                // WHY: Performer struct is (uint256 score, uint256 totalAudits, uint256 successCount,
                //      uint256 failStreak, uint8 status, uint256 registeredAt) = 6 × 32 bytes
                if data.len() >= 6 * 64 {
                    let chunks: Vec<&str> = (0..6).map(|i| &data[i*64..(i+1)*64]).collect();
                    serde_json::json!({
                        "score": abi::hex_to_decimal_string(chunks[0]),
                        "total_audits": abi::hex_to_decimal_string(chunks[1]),
                        "success_count": abi::hex_to_decimal_string(chunks[2]),
                        "fail_streak": abi::hex_to_decimal_string(chunks[3]),
                        "status": abi::hex_to_u8(chunks[4]),
                        "registered_at": abi::hex_to_decimal_string(chunks[5]),
                    })
                } else {
                    serde_json::json!({"status": "no_data"})
                }
            }
            Err(e) => serde_json::json!({"status": "error", "message": format!("{}", e)}),
        }
    } else {
        serde_json::json!({"status": "not_configured", "hint": "Set PORA_REPUTATION_REGISTRY"})
    };

    // 3. Earnings: sum AuditPayoutClaimed events filtered by performer (topic[2])
    let addr_clean = performer_address.trim_start_matches("0x").to_lowercase();
    let performer_topic = format!("0x000000000000000000000000{}", addr_clean);
    let current_block = rpc.eth_block_number().await.unwrap_or(0);
    // WHY: look back 50k blocks (~2 days on Sapphire) for recent earnings.
    //      Longer history requires an indexer; CLI status is for quick checks.
    let from_block = current_block.saturating_sub(50_000);

    let mut claimed_wei: u128 = 0;
    let payout_topic = abi::audit_payout_claimed_topic();
    match rpc.eth_get_logs_chunked(
        &cfg.contract,
        &[Some(payout_topic), None, Some(&performer_topic)],
        from_block, current_block,
    ).await {
        Ok(logs) => {
            for log in &logs {
                let data = log["data"].as_str().unwrap_or("0x");
                let data_clean = data.trim_start_matches("0x");
                if data_clean.len() >= 64 {
                    let amount_hex = &data_clean[..64];
                    let trimmed = amount_hex.trim_start_matches('0');
                    if !trimmed.is_empty() {
                        claimed_wei += u128::from_str_radix(trimmed, 16).unwrap_or(0);
                    }
                }
            }
        }
        Err(_) => {} // earnings unavailable, show 0
    }

    // WHY: show both wei (exact) and ROSE (human-readable) for convenience
    let claimed_rose = claimed_wei as f64 / 1e18;

    Ok(serde_json::json!({
        "address": performer_address,
        "registered": registered,
        "earnings": {
            "claimed_wei": claimed_wei.to_string(),
            "claimed_rose": format!("{:.6}", claimed_rose),
        },
        "reputation": reputation,
        "note": "Active claims not available in v1",
    }))
}

/// Claim audit payout for a completed audit.
// checks: private key configured
// effects: sends claimAuditPayout tx on-chain
// returns: structured JSON with tx hash
// WHY: claimAuditPayout requires either disputeStatus==ResolvedPerformer
//      or (disputeStatus==None && block.timestamp >= lockedUntil).
pub async fn execute_claim_payout(audit_id: u64) -> Result<serde_json::Value> {
    let _key = crate::config::get_private_key()
        .context("Wallet required for claim-payout. Set PORA_PRIVATE_KEY")?;
    let cfg = crate::config::load_config();
    let data = abi::encode_claim_audit_payout(audit_id);
    let (tx_hash, _receipt) = crate::tx::send_and_confirm(&cfg.contract, 0, data, 200_000)
        .await
        .context("claimAuditPayout transaction failed (payout may be locked or already claimed)")?;
    Ok(serde_json::json!({
        "audit_id": audit_id,
        "tx": tx_hash,
    }))
}

/// Release a bounty claim.
// checks: private key configured
// effects: sends releaseBountyClaim tx on-chain
// returns: structured JSON with tx hash
pub async fn execute_release_claim(bounty_id: u64) -> Result<serde_json::Value> {
    let _key = crate::config::get_private_key()
        .context("Wallet required for release-claim. Set PORA_PRIVATE_KEY")?;
    let cfg = crate::config::load_config();
    let data = crate::abi::encode_release_bounty_claim(bounty_id);
    let (tx_hash, _receipt) = crate::tx::send_and_confirm(&cfg.contract, 0, data, 200_000)
        .await
        .context("releaseBountyClaim transaction failed (you may not have an active claim on this bounty)")?;
    Ok(serde_json::json!({
        "bounty_id": bounty_id,
        "tx": tx_hash,
    }))
}

/// Request a bounty claim and wait for TEE confirmation.
// checks: private key configured, performer.json exists
// effects: sends requestClaim tx, polls for BountyClaimAcquired/ClaimRejected events
// returns: structured JSON with claim result (acquired or rejected)
//
// WHY: 2-step claim flow. Local CLI sends requestClaim, then polls for TEE response.
//      This is the performer's entry point to the TEE audit pipeline.
// SECURITY: configHash binds the claim to the performer's actual config.
//           TEE verifies this before confirming — confused-deputy defense.
pub async fn execute_claim(bounty_id: u64, timeout: u64) -> Result<serde_json::Value> {
    let _key = crate::config::get_private_key()
        .context("Wallet required for claim. Set PORA_PRIVATE_KEY")?;
    let cfg = crate::config::load_config();
    let rpc = crate::rpc::RpcClient::new(&cfg.rpc_url);
    let performer_address = resolve_performer_address()?;

    // Step 1: Compute configHash
    let config_hash = compute_config_hash()
        .context("Cannot compute configHash — check performer.json and env vars")?;

    // Step 2: Send requestClaim transaction
    let data = abi::encode_request_claim(bounty_id, &config_hash);
    let (tx_hash, _receipt) = crate::tx::send_and_confirm(&cfg.contract, 0, data, 200_000)
        .await
        .context("requestClaim transaction failed (bounty may not be open or you have a pending claim)")?;

    output::ndjson_event(json!({
        "event": "claim.request_sent",
        "bounty_id": bounty_id,
        "config_hash": format!("0x{}", hex::encode(config_hash)),
        "tx": tx_hash,
    }));

    // Step 3: Poll for TEE response (BountyClaimAcquired or ClaimRejected)
    let addr_clean = performer_address.trim_start_matches("0x").to_lowercase();
    let performer_topic = format!("0x000000000000000000000000{}", addr_clean);
    let bounty_topic = format!("0x{:064x}", bounty_id);

    let poll_interval = tokio::time::Duration::from_secs(3);
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout);
    let start_block = rpc.eth_block_number().await
        .context("Cannot fetch block number for event polling")?;

    loop {
        if tokio::time::Instant::now() >= deadline {
            return Ok(json!({
                "bounty_id": bounty_id,
                "status": "timeout",
                "message": format!("No TEE response within {}s. Claim may still be pending — check with 'pora performer status'", timeout),
                "tx": tx_hash,
            }));
        }

        let current_block = rpc.eth_block_number().await.unwrap_or(start_block);

        // Check for BountyClaimAcquired(uint256 indexed bountyId, address indexed performer)
        if let Ok(logs) = rpc.eth_get_logs_chunked(
            &cfg.contract,
            &[Some(abi::bounty_claim_acquired_topic()), Some(&bounty_topic), Some(&performer_topic)],
            start_block, current_block,
        ).await {
            if !logs.is_empty() {
                return Ok(json!({
                    "bounty_id": bounty_id,
                    "status": "acquired",
                    "message": "Bounty claim confirmed by TEE. Audit will begin shortly.",
                    "tx": tx_hash,
                }));
            }
        }

        // Check for ClaimRejected(uint256 indexed bountyId, address indexed performer, bytes32 reason)
        if let Ok(logs) = rpc.eth_get_logs_chunked(
            &cfg.contract,
            &[Some(abi::claim_rejected_topic()), Some(&bounty_topic), Some(&performer_topic)],
            start_block, current_block,
        ).await {
            if let Some(log) = logs.first() {
                let reason_data = log["data"].as_str().unwrap_or("0x");
                // WHY: reason is keccak256 of a human-readable string (e.g. "CONFIG_MISMATCH").
                //      We can't reverse the hash, but known codes are documented in the spec.
                let reason_hint = match reason_data.get(2..66).unwrap_or("") {
                    s if s == hex::encode(crate::crypto::keccak256(b"CONFIG_MISMATCH")) => "CONFIG_MISMATCH — your configHash doesn't match the TEE's. Check PORA_ROFL_APP_ID/PORA_MODEL/PORA_IMAGE_HASH.",
                    s if s == hex::encode(crate::crypto::keccak256(b"TRUST_POLICY_MISMATCH")) => "TRUST_POLICY_MISMATCH — your provider/model/URL doesn't match the bounty's trust policy.",
                    s if s == hex::encode(crate::crypto::keccak256(b"BOUNTY_UNAVAILABLE")) => "BOUNTY_UNAVAILABLE — bounty is no longer open or trust policy unreadable.",
                    s if s == hex::encode(crate::crypto::keccak256(b"COMPLEXITY_EXCEEDED")) => "COMPLEXITY_EXCEEDED — repository exceeds performer's declared capacity.",
                    _ => "Unknown reason code.",
                };
                return Ok(json!({
                    "bounty_id": bounty_id,
                    "status": "rejected",
                    "reason": reason_data,
                    "reason_hint": reason_hint,
                    "message": format!("Claim rejected by TEE: {}", reason_hint),
                    "tx": tx_hash,
                }));
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(poll_interval) => {},
            _ = tokio::signal::ctrl_c() => {
                return Ok(json!({
                    "bounty_id": bounty_id,
                    "status": "interrupted",
                    "message": "Polling interrupted. Claim may still be pending.",
                    "tx": tx_hash,
                }));
            }
        }
    }
}

/// Initialize performer config.
// checks: provider is valid, API key or Claude OAuth available
// effects: writes ~/.pora/performer.json
// returns: structured JSON with config details
pub fn execute_init(provider: &str, use_claude_login: bool) -> Result<serde_json::Value> {
    let valid_providers = ["anthropic", "openai", "openrouter"];
    if !valid_providers.contains(&provider) {
        anyhow::bail!(
            "Unsupported provider '{}'. Supported: {}",
            provider,
            valid_providers.join(", ")
        );
    }

    if use_claude_login {
        // SECURITY: token bytes are never echoed in output — only subscription metadata.
        if let Some(home) = dirs::home_dir() {
            let creds_path = home.join(".claude").join(".credentials.json");
            if creds_path.exists() {
                let creds: serde_json::Value = serde_json::from_str(
                    &std::fs::read_to_string(&creds_path)?
                )?;
                if let Some(oauth) = creds.get("claudeAiOauth") {
                    if oauth.get("accessToken").and_then(|t| t.as_str()).is_some() {
                        let sub_type = oauth.get("subscriptionType")
                            .and_then(|s| s.as_str())
                            .unwrap_or("unknown");
                        let api_key_source = format!("claude-oauth ({})", sub_type);

                        save_performer_config(None, provider, &api_key_source)?;

                        return Ok(serde_json::json!({
                            "provider": provider,
                            "api_key_source": api_key_source,
                            "subscription": sub_type,
                            "message": "Claude Code OAuth token detected. Config saved to ~/.pora/performer.json. No additional API costs."
                        }));
                    }
                }
            }
        }
        anyhow::bail!("Claude Code credentials not found at ~/.claude/.credentials.json. Run 'claude' and log in first.");
    }

    let env_var = match provider {
        "anthropic" => "ANTHROPIC_API_KEY",
        "openai" => "OPENAI_API_KEY",
        "openrouter" => "OPENROUTER_API_KEY",
        _ => unreachable!(),
    };

    if std::env::var(env_var).is_ok() {
        let api_key_source = format!("env:{}", env_var);
        save_performer_config(None, provider, &api_key_source)?;
        Ok(serde_json::json!({
            "provider": provider,
            "api_key_source": api_key_source,
            "message": format!("{} detected. Config saved to ~/.pora/performer.json", env_var),
        }))
    } else {
        let hint = if provider == "anthropic" {
            format!("Set {} or use --use-claude-login", env_var)
        } else {
            format!("Set {} environment variable", env_var)
        };
        anyhow::bail!("No API key found for provider '{}'. {}", provider, hint);
    }
}

/// Snapshot of performer events (MCP-friendly version of start --once).
// checks: performer address available
// effects: read-only RPC calls
// returns: collected events as JSON
pub async fn execute_monitor() -> Result<serde_json::Value> {
    let cfg = config::load_config();
    let rpc = crate::rpc::RpcClient::new(&cfg.rpc_url);
    let performer_address = resolve_performer_address()?;

    let addr_clean = performer_address.trim_start_matches("0x").to_lowercase();
    let performer_topic = format!("0x000000000000000000000000{}", addr_clean);

    const LOOKBACK: u64 = 50_000;
    let current = rpc.eth_block_number().await?;
    let from_block = current.saturating_sub(LOOKBACK);

    let mut events: Vec<serde_json::Value> = Vec::new();

    // AuditPayoutClaimed — performer is topic[2]
    if let Ok(logs) = rpc.eth_get_logs_chunked(
        &cfg.contract,
        &[Some(abi::audit_payout_claimed_topic()), None, Some(&performer_topic)],
        from_block, current,
    ).await {
        for log in logs {
            events.push(json!({"event": "payout.claimed", "log": log}));
        }
    }

    // Events without performer index
    for (topic0, event_name) in [
        (abi::audit_submitted_topic(), "audit.submitted"),
        (abi::audit_result_submitted_topic(), "audit.result_submitted"),
        (abi::audit_delivery_recorded_topic(), "audit.delivery_recorded"),
    ] {
        if let Ok(logs) = rpc.eth_get_logs_chunked(
            &cfg.contract, &[Some(topic0)],
            from_block, current,
        ).await {
            for log in logs {
                events.push(json!({"event": event_name, "log": log}));
            }
        }
    }

    let count = events.len();
    Ok(json!({
        "performer": performer_address,
        "events": events,
        "count": count,
        "from_block": from_block,
        "to_block": current,
    }))
}

pub async fn run(action: PerformerAction, format: &Format) -> Result<()> {
    match action {
        PerformerAction::Init { provider, use_claude_login } => {
            let data = execute_init(&provider, use_claude_login)?;
            output::print_success(format, "performer.init", &data);
        }
        PerformerAction::Start { interval, once } => {
            // WHY: streaming command outputs directly to stdout as NDJSON
            execute_start(interval, once).await?;
        }
        PerformerAction::Status => {
            let data = execute_status().await?;
            output::print_success(format, "performer.status", &data);
        }
        PerformerAction::ClaimPayout { audit_id } => {
            let data = execute_claim_payout(audit_id).await?;
            output::print_success(format, "performer.claim_payout", &data);
        }
        PerformerAction::ReleaseClaim { bounty_id } => {
            let data = execute_release_claim(bounty_id).await?;
            output::print_success(format, "performer.release_claim", &data);
        }
        PerformerAction::Claim { bounty_id, timeout } => {
            let data = execute_claim(bounty_id, timeout).await?;
            output::print_success(format, "performer.claim", &data);
        }
    }
    Ok(())
}
