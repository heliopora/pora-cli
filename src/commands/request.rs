use anyhow::{Context, Result};
use clap::Subcommand;

use crate::abi;
use crate::config;
use crate::contract;
use crate::github;
use crate::output::{self, Format};
use crate::tx;

#[derive(Subcommand)]
pub enum RequestAction {
    /// Create a bounty + configure repo + set delivery (atomic)
    Submit {
        /// Repository in owner/repo format
        repo: String,
        /// Amount of ROSE to deposit
        #[arg(long, default_value = "1.0")]
        amount: f64,
        /// Trigger mode: on-change, periodic
        #[arg(long, default_value = "on-change")]
        trigger: String,
        /// Audit mode: static, tee-local, tee-api
        #[arg(long, default_value = "tee-api")]
        mode: String,
        /// Bounty duration in hours
        #[arg(long, default_value = "168")]
        duration_hours: u64,
        /// Standing bounty (repeating audits from pool)
        #[arg(long)]
        standing: bool,
        /// GitHub App installation ID (auto-detected if not provided)
        #[arg(long)]
        installation_id: Option<u64>,
        /// Period in days for periodic trigger (required if --trigger periodic)
        #[arg(long, default_value = "7")]
        period_days: u64,
    },
    /// List bounties on the market
    List {
        /// Include closed/cancelled bounties
        #[arg(long)]
        all: bool,
    },
    /// Watch a bounty for audit completion (streams NDJSON events)
    Watch {
        /// Bounty ID
        bounty_id: u64,
        /// Poll interval in seconds
        #[arg(long, default_value = "5")]
        interval: u64,
        /// Emit current events then exit
        #[arg(long)]
        once: bool,
    },
    /// Download and decrypt audit results
    Results {
        /// Audit ID
        audit_id: u64,
        /// Path to X25519 private key (auto-detected from ~/.pora/keys/ if omitted)
        #[arg(long)]
        key: Option<String>,
        /// Output raw plaintext without JSON wrapper
        #[arg(long)]
        raw: bool,
    },
}

// checks: trigger string is one of: on-change, periodic
// effects: none
// returns: trigger mode bitflag (0x01=ON_CHANGE, 0x08=PERIODIC)
fn parse_trigger_mode(trigger: &str) -> Result<u8> {
    match trigger {
        "on-change" => Ok(0x01),
        "periodic" => Ok(0x08),
        _ => anyhow::bail!(
            "Invalid trigger mode '{}'. Supported: on-change, periodic",
            trigger
        ),
    }
}

// checks: mode string is one of: static, tee-local, tee-api
// effects: none
// returns: tool mode (1=Semgrep, 2=Semgrep+LLM, 3=LLM full)
fn parse_tool_mode(mode: &str) -> Result<u8> {
    match mode {
        "static" => Ok(1),
        "tee-local" => Ok(2),
        "tee-api" => Ok(3),
        _ => anyhow::bail!(
            "Invalid audit mode '{}'. Supported: static, tee-local, tee-api",
            mode
        ),
    }
}

// checks: amount is non-negative
// effects: none
// returns: amount in wei (1 ROSE = 10^18 wei)
// WHY: f64 * 1e18 loses precision for fractional amounts (0.1 ROSE → 99999999999999998 wei).
//      Integer arithmetic avoids this by splitting whole/fractional parts.
fn rose_to_wei(amount: f64) -> Result<u128> {
    if amount < 0.0 {
        anyhow::bail!("Amount must be non-negative");
    }
    // Format with 18 decimal places to capture full precision
    let s = format!("{:.18}", amount);
    let parts: Vec<&str> = s.split('.').collect();
    let whole: u128 = parts[0].parse().unwrap_or(0);
    let frac_str = if parts.len() > 1 { parts[1] } else { "0" };
    // Pad or truncate to exactly 18 digits
    let padded = format!("{:0<18}", &frac_str[..frac_str.len().min(18)]);
    let frac: u128 = padded.parse().unwrap_or(0);
    Ok(whole * 1_000_000_000_000_000_000 + frac)
}

// checks: repo is in "owner/repo" format
// effects: none
// returns: (owner, repo) tuple
fn parse_repo(repo: &str) -> Result<(&str, &str)> {
    let parts: Vec<&str> = repo.splitn(2, '/').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        anyhow::bail!(
            "Invalid repo format '{}'. Expected: owner/repo (e.g. acme/api)",
            repo
        );
    }
    Ok((parts[0], parts[1]))
}

/// Execute the atomic submit flow: createBounty → setRepoInfo → setAuditConfig → setDeliveryConfig.
// checks: private key configured, RPC reachable, valid args
// effects: sends 3-4 transactions on-chain, creates bounty with full config
// returns: structured JSON with bounty_id and tx hashes
// SECURITY: transactions are signed locally — private key never leaves the CLI
async fn execute_submit(
    repo: &str,
    amount: f64,
    trigger: &str,
    mode: &str,
    duration_hours: u64,
    standing: bool,
    installation_id: Option<u64>,
    period_days: u64,
    format: &Format,
) -> Result<()> {
    let (owner, repo_name) = parse_repo(repo)?;
    let trigger_mode = parse_trigger_mode(trigger)?;
    let tool_mode = parse_tool_mode(mode)?;

    // Resolve GitHub installation ID (AD-4: 5-level fallback)
    let install_id =
        github::resolve_installation_id(owner, repo_name, installation_id).await?;

    let cfg = config::load_config();
    let amount_wei = rose_to_wei(amount)?;
    let duration_secs = duration_hours * 3600;

    let repo_hash = abi::repo_hash(owner, repo_name);

    let mut tx_hashes: Vec<String> = Vec::new();

    // Step 1: createBounty (payable)
    let create_data =
        abi::encode_create_bounty(&repo_hash, duration_secs, standing);
    let (create_tx, create_receipt) =
        tx::send_and_confirm(&cfg.contract, amount_wei, create_data, 300_000)
            .await
            .context("createBounty transaction failed")?;
    tx_hashes.push(create_tx.clone());

    // Extract bountyId from return value or logs
    // WHY: createBounty returns uint256 bountyId. We extract it from the
    //      BountyCreated event log (topic[1] = bountyId).
    let bounty_id = extract_bounty_id_from_receipt(&create_receipt)?;

    // Step 2: setRepoInfo
    let repo_info_data =
        abi::encode_set_repo_info(bounty_id, owner, repo_name, install_id);
    match tx::send_and_confirm(&cfg.contract, 0, repo_info_data, 200_000).await {
        Ok((hash, _)) => tx_hashes.push(hash),
        Err(e) => {
            return report_partial_failure(
"setRepoInfo",
                bounty_id,
                &tx_hashes,
                e,
            );
        }
    }

    // Step 3: setAuditConfig
    let scope_mode: u8 = 0; // default scope
    let period = if trigger_mode == 0x08 {
        period_days
    } else {
        0
    };
    let audit_config_data = abi::encode_set_audit_config(
        bounty_id,
        trigger_mode,
        scope_mode,
        tool_mode,
        period,
    );
    match tx::send_and_confirm(&cfg.contract, 0, audit_config_data, 200_000).await
    {
        Ok((hash, _)) => tx_hashes.push(hash),
        Err(e) => {
            return report_partial_failure(
"setAuditConfig",
                bounty_id,
                &tx_hashes,
                e,
            );
        }
    }

    // Step 4: setDeliveryConfig (RequesterOnly mode with placeholder keys for now)
    // WHY: we use a zero pubkey placeholder — real X25519 keygen comes in a later story.
    //      The contract requires a non-zero key, so we use a dummy 0x01-prefixed key.
    let mut encryption_pub_key = [0u8; 32];
    encryption_pub_key[0] = 0x01; // placeholder non-zero
    let notification_policy_hash = [0u8; 32];
    let delivery_mode: u8 = 1; // RequesterOnly

    let delivery_data = abi::encode_set_delivery_config(
        bounty_id,
        &encryption_pub_key,
        &notification_policy_hash,
        delivery_mode,
    );
    match tx::send_and_confirm(&cfg.contract, 0, delivery_data, 200_000).await {
        Ok((hash, _)) => tx_hashes.push(hash),
        Err(e) => {
            return report_partial_failure(
"setDeliveryConfig",
                bounty_id,
                &tx_hashes,
                e,
            );
        }
    }

    // All 4 transactions succeeded
    let result = serde_json::json!({
        "bounty_id": bounty_id,
        "repo": format!("{}/{}", owner, repo_name),
        "installation_id": install_id,
        "amount": format!("{} ROSE", amount),
        "amount_wei": amount_wei.to_string(),
        "trigger": trigger,
        "mode": mode,
        "standing": standing,
        "duration_hours": duration_hours,
        "delivery": "encrypted",
        "transactions": tx_hashes,
    });
    output::print_success(format, "request.submit", &result);
    Ok(())
}

// checks: receipt has logs with BountyCreated event
// effects: none
// returns: bountyId extracted from event log
// WHY: BountyCreated(uint256 indexed bountyId, address indexed requester, uint256 amount, bool standing)
//      topic[0] = keccak256("BountyCreated(uint256,address,uint256,bool)")
//      topic[1] = bountyId (indexed)
// SECURITY: we verify topic[0] matches the BountyCreated event signature to avoid
//           extracting the wrong value if the contract emits other events.
fn extract_bounty_id_from_receipt(receipt: &tx::TxReceipt) -> Result<u64> {
    use crate::crypto::keccak256;
    let event_sig = keccak256(b"BountyCreated(uint256,address,uint256,bool)");
    let event_sig_hex = format!("0x{}", hex::encode(event_sig));

    for log in &receipt.logs {
        if let Some(topics) = log["topics"].as_array() {
            if topics.len() >= 2 {
                let topic0 = topics[0].as_str().unwrap_or("");
                if topic0 != event_sig_hex {
                    continue;
                }
                // topic[1] = bountyId (indexed)
                let hex_str = topics[1]
                    .as_str()
                    .unwrap_or("0x0")
                    .strip_prefix("0x")
                    .unwrap_or("0");
                let id = u64::from_str_radix(hex_str, 16).unwrap_or(0);
                if id > 0 {
                    return Ok(id);
                }
            }
        }
    }
    anyhow::bail!("Could not extract bountyId from createBounty receipt. No BountyCreated event found.")
}

// checks: none
// effects: none
// returns: Err with structured partial failure context
fn report_partial_failure(
    failed_step: &str,
    bounty_id: u64,
    successful_txs: &[String],
    error: anyhow::Error,
) -> Result<()> {
    anyhow::bail!(
        "PARTIAL_SUBMIT_FAILURE: {} failed after bounty #{} was created. \
         Successful txs: [{}]. Error: {}. \
         Retry the failed step or re-run submit.",
        failed_step,
        bounty_id,
        successful_txs.join(", "),
        error
    )
}

/// Stream audit events for a bounty as NDJSON.
// checks: bounty_id is valid, RPC reachable
// effects: polls eth_getLogs, emits NDJSON to stdout
async fn execute_watch(bounty_id: u64, interval: u64, once: bool) -> Result<()> {
    let cfg = config::load_config();
    let rpc = crate::rpc::RpcClient::new(&cfg.rpc_url);
    let bounty_id_hex = format!("0x{:064x}", bounty_id);

    // WHY: most RPC nodes reject eth_getLogs over >100k block ranges.
    //      For --once, look back 50k blocks (~2 days on Sapphire).
    const ONCE_LOOKBACK: u64 = 50_000;
    let current = rpc.eth_block_number().await?;
    let mut from_block = if once { current.saturating_sub(ONCE_LOOKBACK) } else { current };
    let sleep_dur = tokio::time::Duration::from_secs(interval);

    loop {
        let to_block = rpc.eth_block_number().await.unwrap_or(from_block);

        if to_block >= from_block {
            let from_hex = format!("0x{:x}", from_block);
            let to_hex = format!("0x{:x}", to_block);

            // Events indexed by bountyId in topic[1]
            for (topic0, event_name) in abi::bounty_event_topics() {
                rpc.fetch_and_emit_logs(
                    &cfg.contract, &[Some(topic0), Some(&bounty_id_hex)],
                    &from_hex, &to_hex, event_name,
                ).await;
            }

            // Events indexed by bountyId in topic[2]
            for (topic0, event_name) in abi::audit_event_topics_by_bounty() {
                rpc.fetch_and_emit_logs(
                    &cfg.contract, &[Some(topic0), None, Some(&bounty_id_hex)],
                    &from_hex, &to_hex, event_name,
                ).await;
            }

            // Events without bountyId index — fetch all, client correlates via auditId
            for (topic0, event_name) in [
                (abi::audit_payout_claimed_topic(), "payout.claimed"),
                (abi::audit_delivery_recorded_topic(), "audit.delivery_recorded"),
            ] {
                rpc.fetch_and_emit_logs(
                    &cfg.contract, &[Some(topic0)],
                    &from_hex, &to_hex, event_name,
                ).await;
            }

            from_block = to_block + 1;
        }

        if once { return Ok(()); }

        tokio::select! {
            _ = tokio::time::sleep(sleep_dur) => {},
            _ = tokio::signal::ctrl_c() => { return Ok(()); }
        }
    }
}

/// Download and decrypt audit results.
// SECURITY: private key never leaves local machine. Decryption happens client-side only.
// TRUST: on-chain hashes are integrity anchors. If gateway tampers with ciphertext, hash check fails.
async fn execute_results(audit_id: u64, key: Option<String>, raw: bool, format: &Format) -> Result<()> {
    let cfg = config::load_config();
    let gateway_url = cfg.gateway_url.as_deref()
        .context("gateway_url not set in config")?;
    let rpc = crate::rpc::RpcClient::new(&cfg.rpc_url);

    // Step 1: Query on-chain delivery info
    let delivery_hex = rpc.eth_call(&cfg.contract, &abi::encode_get_audit_delivery(audit_id)).await?;
    let delivery = abi::decode_audit_delivery(&delivery_hex)
        .context("No delivery found for this audit")?;

    // Step 2: Get bountyId from audit struct, then delivery config pubkey
    let audit_hex = rpc.eth_call(&cfg.contract, &abi::encode_get_audit(audit_id)).await?;
    let bounty_id = abi::decode_audit_bounty_id(&audit_hex)
        .context("Audit not found")?;
    let config_hex = rpc.eth_call(&cfg.contract, &abi::encode_get_delivery_config(bounty_id)).await?;
    let onchain_pubkey = abi::decode_delivery_config_pubkey(&config_hex);

    // Step 3: Load private key
    let secret_key = crate::crypto::load_private_key(key.as_deref(), onchain_pubkey.as_deref())?;

    // Step 4: Download ciphertext + manifest from gateway (parallel)
    let client = reqwest::Client::new();
    let enc_url = format!("{}/delivery/{}.enc.json", gateway_url, audit_id);
    let manifest_url = format!("{}/delivery/{}.manifest.json", gateway_url, audit_id);

    let (enc_result, manifest_result) = tokio::join!(
        client.get(&enc_url).send(),
        client.get(&manifest_url).send(),
    );

    let enc_resp = enc_result.context("Failed to fetch ciphertext")?;
    anyhow::ensure!(enc_resp.status().is_success(), "GET {} returned {}", enc_url, enc_resp.status());
    let enc_bytes = enc_resp.bytes().await?;

    let manifest_resp = manifest_result.context("Failed to fetch manifest")?;
    anyhow::ensure!(manifest_resp.status().is_success(), "GET {} returned {}", manifest_url, manifest_resp.status());
    let manifest_bytes = manifest_resp.bytes().await?;

    // Step 5: Verify hashes against on-chain anchors
    let ct_hash = hex::encode(crate::crypto::keccak256(&enc_bytes));
    anyhow::ensure!(
        ct_hash == delivery.ciphertext_hash.trim_start_matches("0x"),
        "ciphertext hash mismatch: gateway data differs from on-chain anchor"
    );
    let mf_hash = hex::encode(crate::crypto::keccak256(&manifest_bytes));
    anyhow::ensure!(
        mf_hash == delivery.manifest_hash.trim_start_matches("0x"),
        "manifest hash mismatch: gateway data differs from on-chain anchor"
    );

    // Step 6: Parse manifest
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)?;
    let ephemeral_pubkey_hex = manifest["ephemeral_pubkey"].as_str().unwrap_or_default();
    let nonce_hex = manifest["nonce"].as_str().unwrap_or_default();
    let receipt_hash_hex = manifest["receipt_hash"].as_str().unwrap_or_default();

    // Step 7: Decrypt
    let plaintext = crate::crypto::decrypt_delivery(&secret_key, ephemeral_pubkey_hex, nonce_hex, &enc_bytes)?;

    // Step 8: Verify plaintext hash
    if !receipt_hash_hex.is_empty() {
        let pt_hash = hex::encode(crate::crypto::keccak256(&plaintext));
        anyhow::ensure!(
            pt_hash == receipt_hash_hex.trim_start_matches("0x"),
            "plaintext hash mismatch: decrypted content does not match receiptHash"
        );
    }

    // Step 9: Output
    if raw {
        print!("{}", String::from_utf8_lossy(&plaintext));
    } else {
        let report: serde_json::Value = serde_json::from_slice(&plaintext)
            .unwrap_or(serde_json::json!({"raw": String::from_utf8_lossy(&plaintext)}));
        output::print_success(format, "request.results", &serde_json::json!({
            "audit_id": audit_id,
            "bounty_id": bounty_id,
            "report": report,
        }));
    }
    Ok(())
}

pub async fn run(action: RequestAction, format: &Format) -> Result<()> {
    match action {
        RequestAction::Submit {
            repo,
            amount,
            trigger,
            mode,
            duration_hours,
            standing,
            installation_id,
            period_days,
        } => {
            execute_submit(
                &repo,
                amount,
                &trigger,
                &mode,
                duration_hours,
                standing,
                installation_id,
                period_days,
                format,
            )
            .await?;
        }
        RequestAction::List { all } => {
            let bounties = contract::list_bounties(!all).await?;
            output::print_success(
                format,
                "request.list",
                &serde_json::json!({
                    "bounties": bounties,
                    "count": bounties.len(),
                }),
            );
        }
        RequestAction::Watch { bounty_id, interval, once } => {
            execute_watch(bounty_id, interval, once).await?;
        }
        RequestAction::Results { audit_id, key, raw } => {
            execute_results(audit_id, key, raw, format).await?;
        }
    }
    Ok(())
}
