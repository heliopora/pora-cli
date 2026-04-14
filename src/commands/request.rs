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
        /// Repo access mode: auto, public, token, app
        /// auto: detect visibility (public repos skip GitHub App)
        /// public: no auth needed (public repos only)
        /// token: use --token PAT for private repo access
        /// app: use GitHub App installation (existing behavior)
        #[arg(long, default_value = "auto")]
        access: String,
        /// GitHub PAT for private repo access without GitHub App.
        /// Use '-' to read from stdin.
        #[arg(long)]
        token: Option<String>,
    },
    /// Cancel a bounty and reclaim escrowed funds
    Cancel {
        /// Bounty ID to cancel
        bounty_id: u64,
    },
    /// Top up a standing bounty's pool (standing bounties only)
    TopUp {
        /// Bounty ID to top up
        bounty_id: u64,
        /// Amount of ROSE to add
        #[arg(long)]
        amount: f64,
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
    /// Dispute an audit result (requester only, within challenge window)
    Dispute {
        /// Audit ID to dispute
        audit_id: u64,
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

// checks: amount is greater than zero
// effects: none
// returns: amount in wei (1 ROSE = 10^18 wei)
// WHY: f64 * 1e18 loses precision for fractional amounts (0.1 ROSE → 99999999999999998 wei).
//      Integer arithmetic avoids this by splitting whole/fractional parts.
fn rose_to_wei(amount: f64) -> Result<u128> {
    if amount <= 0.0 {
        anyhow::bail!("Amount must be greater than zero");
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
// checks: access is one of: auto, public, token, app
// effects: none
// returns: validated access mode string
fn validate_access_mode<'a>(access: &'a str, token: &Option<String>) -> Result<&'a str> {
    match access {
        "auto" | "public" | "token" | "app" => {}
        _ => anyhow::bail!(
            "Invalid access mode '{}'. Supported: auto, public, token, app",
            access
        ),
    }
    if access == "token" && token.is_none() {
        anyhow::bail!("--access token requires --token <PAT>. Use --token ghp_xxx or --token - for stdin.");
    }
    Ok(access)
}

/// Resolve repo access: returns (installation_id, access_mode_label) based on --access flag.
// checks: access mode is valid, repo exists if auto-detect
// effects: may query GitHub API for visibility check
// returns: (installation_id, access_mode_string)
// WHY: different access modes need different installation IDs.
//      public=0 (TEE clones without auth), token=0 (TEE uses stored PAT), app=resolved ID.
async fn resolve_repo_access(
    owner: &str,
    repo: &str,
    access: &str,
    token: &Option<String>,
    installation_id: Option<u64>,
) -> Result<(u64, String)> {
    match access {
        "public" => Ok((0, "public".to_string())),
        "token" => {
            // WHY: with PAT-based access, the TEE will use the stored token.
            //      installationId=0 signals "not using GitHub App".
            Ok((0, "token".to_string()))
        }
        "app" => {
            let id = github::resolve_installation_id(owner, repo, installation_id).await?;
            Ok((id, "app".to_string()))
        }
        "auto" => {
            // WHY: auto-detect repo visibility. Public repos skip GitHub App entirely.
            //      unwrap_or(false) treats API failures the same as private repos.
            let is_public = github::check_repo_visibility(owner, repo).await.unwrap_or(false);
            if is_public {
                Ok((0, "public".to_string()))
            } else if token.is_some() {
                Ok((0, "token".to_string()))
            } else {
                let id = github::resolve_installation_id(owner, repo, installation_id).await?;
                Ok((id, "app".to_string()))
            }
        }
        _ => unreachable!(), // validated above
    }
}

/// Read a token from the --token flag value, supporting '-' for stdin.
// checks: token is non-empty
// effects: may read from stdin
// returns: token string
fn read_token(token_value: &str) -> Result<String> {
    if token_value == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        let trimmed = buf.trim().to_string();
        anyhow::ensure!(!trimmed.is_empty(), "Empty token from stdin");
        Ok(trimmed)
    } else {
        Ok(token_value.to_string())
    }
}

/// Save a repo access token (base64-encoded) to ~/.pora/tokens/{bounty_id}.token.
// checks: token is non-empty
// effects: creates ~/.pora/tokens/ if needed, writes base64-encoded token file with 0600 permissions
// SECURITY: token is NOT encrypted — protected by file permissions only (0600 on Unix).
//           This is a local convenience store for testnet. Production will use Sapphire's
//           confidential storage for on-chain token storage.
fn save_repo_token(bounty_id: u64, token: &str) -> Result<()> {
    let dir = config::config_dir().join("tokens");
    std::fs::create_dir_all(&dir)?;
    // WHY: for now, store the token as base64-encoded plaintext in a restricted file.
    //      Full encryption with the delivery X25519 key requires contract-side changes.
    //      File permissions (0600) provide local protection.
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, token.as_bytes());
    let path = dir.join(format!("{}.token", bounty_id));
    std::fs::write(&path, &encoded)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

pub async fn execute_submit(
    repo: &str,
    amount: f64,
    trigger: &str,
    mode: &str,
    duration_hours: u64,
    standing: bool,
    installation_id: Option<u64>,
    period_days: u64,
    access: &str,
    token: &Option<String>,
) -> Result<serde_json::Value> {
    // WHY: fail fast on missing wallet before reaching GitHub or RPC calls.
    //      Users without a wallet should get clear guidance, not GitHub 401.
    let _private_key = crate::config::get_private_key()
        .context("Wallet required for submit. Set PORA_PRIVATE_KEY or add private_key to ~/.pora/config.toml")?;

    let amount_wei = rose_to_wei(amount)?;
    let (owner, repo_name) = parse_repo(repo)?;
    let trigger_mode = parse_trigger_mode(trigger)?;
    let tool_mode = parse_tool_mode(mode)?;
    let access = validate_access_mode(access, token)?;

    // Resolve repo access (may skip GitHub App for public/token modes)
    let (install_id, access_label) = resolve_repo_access(
        owner, repo_name, access, token, installation_id,
    ).await?;

    // Read token from value (supports '-' for stdin)
    let resolved_token = if let Some(t) = token {
        Some(read_token(t)?)
    } else {
        None
    };

    let cfg = config::load_config();
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

    // Step 4: setDeliveryConfig with real X25519 public key
    // WHY: auto-generate keypair on first submit so users get encrypted delivery
    //      without a separate setup step. The backup warning is critical — losing
    //      the private key means losing access to audit results.
    let encryption_pub_key = if crate::crypto::delivery_keys_exist() {
        crate::crypto::load_delivery_pubkey()?
    } else {
        let (priv_path, _pub_path) = crate::crypto::generate_x25519_keypair()?;
        eprintln!(
            "Generated X25519 delivery key at {} — BACK UP THIS FILE, it is required to decrypt audit results",
            priv_path.display()
        );
        crate::crypto::load_delivery_pubkey()?
    };
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

    // Save token locally if provided
    if let Some(ref tok) = resolved_token {
        if let Err(e) = save_repo_token(bounty_id, tok) {
            // WHY: token save failure is non-fatal — the bounty is already created.
            //      Warn but don't fail the entire submit flow.
            eprintln!("Warning: could not save token locally: {}", e);
        }
    }

    // All 4 transactions succeeded
    Ok(serde_json::json!({
        "bounty_id": bounty_id,
        "repo": format!("{}/{}", owner, repo_name),
        "access_mode": access_label,
        "installation_id": install_id,
        "amount": format!("{} ROSE", amount),
        "amount_wei": amount_wei.to_string(),
        "trigger": trigger,
        "mode": mode,
        "standing": standing,
        "duration_hours": duration_hours,
        "delivery": "encrypted",
        "transactions": tx_hashes,
    }))
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
fn report_partial_failure<T>(
    failed_step: &str,
    bounty_id: u64,
    successful_txs: &[String],
    error: anyhow::Error,
) -> Result<T> {
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

/// Cancel a bounty and reclaim escrowed funds.
// checks: private key configured, bounty_id > 0
// effects: sends cancelBounty tx on-chain
// returns: structured JSON with tx hash
pub async fn execute_cancel(bounty_id: u64) -> Result<serde_json::Value> {
    let _key = crate::config::get_private_key()
        .context("Wallet required for cancel. Set PORA_PRIVATE_KEY")?;
    let cfg = config::load_config();
    let data = abi::encode_cancel_bounty(bounty_id);
    let (tx_hash, _receipt) = tx::send_and_confirm(&cfg.contract, 0, data, 200_000)
        .await
        .context("cancelBounty transaction failed")?;
    Ok(serde_json::json!({
        "bounty_id": bounty_id,
        "tx": tx_hash,
    }))
}

/// Top up a standing bounty's pool.
// checks: private key configured, amount > 0
// effects: sends topUpBounty tx on-chain with ROSE value
// returns: structured JSON with tx hash and amount
// WHY: topUpBounty(uint256) requires bounty.standing — non-standing bounties will revert.
pub async fn execute_topup(bounty_id: u64, amount: f64) -> Result<serde_json::Value> {
    let _key = crate::config::get_private_key()
        .context("Wallet required for topup. Set PORA_PRIVATE_KEY")?;
    let amount_wei = rose_to_wei(amount)?;
    let cfg = config::load_config();
    let data = abi::encode_top_up_bounty(bounty_id);
    let (tx_hash, _receipt) = tx::send_and_confirm(&cfg.contract, amount_wei, data, 200_000)
        .await
        .context("topUpBounty transaction failed (is this a standing bounty?)")?;
    Ok(serde_json::json!({
        "bounty_id": bounty_id,
        "amount": format!("{} ROSE", amount),
        "amount_wei": amount_wei.to_string(),
        "tx": tx_hash,
    }))
}

/// Dispute an audit result.
// checks: private key configured
// effects: sends disputeAudit tx on-chain
// returns: structured JSON with tx hash
pub async fn execute_dispute(audit_id: u64) -> Result<serde_json::Value> {
    let _key = crate::config::get_private_key()
        .context("Wallet required for dispute. Set PORA_PRIVATE_KEY")?;
    let cfg = config::load_config();
    let data = abi::encode_dispute_audit(audit_id);
    let (tx_hash, _receipt) = tx::send_and_confirm(&cfg.contract, 0, data, 200_000)
        .await
        .context("disputeAudit transaction failed (audit may not exist, not in disputable state, or challenge window expired)")?;
    Ok(serde_json::json!({
        "audit_id": audit_id,
        "tx": tx_hash,
    }))
}

/// Stream audit events for a bounty as NDJSON.
// checks: bounty_id is valid, RPC reachable
// effects: polls eth_getLogs, emits NDJSON to stdout
// returns: Ok(()) on success; Err if --once and zero events found across all fetches
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

    // WHY: track total events only for --once exit-code check; continuous mode never bails on zero.
    let mut total_events: usize = 0;

    loop {
        let to_block = rpc.eth_block_number().await.unwrap_or(from_block);

        if to_block >= from_block {
            // Events indexed by bountyId in topic[1]
            for (topic0, event_name) in abi::bounty_event_topics() {
                total_events += rpc.fetch_and_emit_logs(
                    &cfg.contract, &[Some(topic0), Some(&bounty_id_hex)],
                    from_block, to_block, event_name,
                ).await;
            }

            // Events indexed by bountyId in topic[2]
            for (topic0, event_name) in abi::audit_event_topics_by_bounty() {
                total_events += rpc.fetch_and_emit_logs(
                    &cfg.contract, &[Some(topic0), None, Some(&bounty_id_hex)],
                    from_block, to_block, event_name,
                ).await;
            }

            // Events without bountyId index — fetch all, client correlates via auditId
            for (topic0, event_name) in [
                (abi::audit_payout_claimed_topic(), "payout.claimed"),
                (abi::audit_delivery_recorded_topic(), "audit.delivery_recorded"),
            ] {
                total_events += rpc.fetch_and_emit_logs(
                    &cfg.contract, &[Some(topic0)],
                    from_block, to_block, event_name,
                ).await;
            }

            from_block = to_block + 1;
        }

        if once {
            // WHY: exit non-zero so scripts consuming NDJSON can detect all-fail scenarios.
            //      Zero events means either no history in the lookback window or all RPC calls failed.
            if total_events == 0 {
                anyhow::bail!(
                    "No events found for bounty #{} in the last {} blocks",
                    bounty_id,
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

/// Download and decrypt audit results.
// SECURITY: private key never leaves local machine. Decryption happens client-side only.
// TRUST: on-chain hashes are integrity anchors. If gateway tampers with ciphertext, hash check fails.
pub async fn execute_results(audit_id: u64, key: Option<String>, raw: bool) -> Result<serde_json::Value> {
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
    let report: serde_json::Value = if raw {
        serde_json::json!({"raw": String::from_utf8_lossy(&plaintext)})
    } else {
        serde_json::from_slice(&plaintext)
            .unwrap_or(serde_json::json!({"raw": String::from_utf8_lossy(&plaintext)}))
    };
    Ok(serde_json::json!({
        "audit_id": audit_id,
        "bounty_id": bounty_id,
        "report": report,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rose_to_wei_zero_rejected() {
        assert!(rose_to_wei(0.0).is_err());
    }

    #[test]
    fn test_rose_to_wei_positive() {
        assert_eq!(rose_to_wei(1.0).unwrap(), 1_000_000_000_000_000_000u128);
    }

    #[test]
    fn test_rose_to_wei_fractional() {
        // WHY: f64 cannot represent 0.1 exactly; format!("{:.18}", 0.1) yields
        //      "0.100000000000000005551..." which rounds the last digit up.
        //      We test the actual output of the integer-split algorithm, not an
        //      idealized value, so callers know what precision to expect.
        let wei = rose_to_wei(0.1).unwrap();
        assert!(
            wei >= 99_999_999_999_999_990 && wei <= 100_000_000_000_000_010,
            "0.1 ROSE should be within 10 wei of 0.1 * 10^18, got {}",
            wei
        );
    }

    #[test]
    fn test_validate_access_mode_valid() {
        for mode in ["auto", "public", "token", "app"] {
            let token = if mode == "token" { Some("ghp_xxx".to_string()) } else { None };
            assert!(validate_access_mode(mode, &token).is_ok(), "mode '{}' should be valid", mode);
        }
    }

    #[test]
    fn test_validate_access_mode_invalid() {
        assert!(validate_access_mode("invalid", &None).is_err());
    }

    #[test]
    fn test_validate_access_mode_token_requires_token() {
        assert!(validate_access_mode("token", &None).is_err());
    }

    #[test]
    fn test_rose_to_wei_negative_rejected() {
        assert!(rose_to_wei(-1.0).is_err());
    }

    #[test]
    fn test_parse_repo_valid() {
        let (owner, repo) = parse_repo("acme/api").unwrap();
        assert_eq!(owner, "acme");
        assert_eq!(repo, "api");
    }

    #[test]
    fn test_parse_repo_invalid() {
        assert!(parse_repo("invalid").is_err());
        assert!(parse_repo("").is_err());
        assert!(parse_repo("/").is_err());
        assert!(parse_repo("owner/").is_err());
        assert!(parse_repo("/repo").is_err());
    }
}

/// List bounties on the market.
// checks: RPC reachable
// effects: none (read-only)
// returns: bounty array with count
pub async fn execute_list(all: bool) -> Result<serde_json::Value> {
    let bounties = contract::list_bounties(!all).await?;
    Ok(serde_json::json!({
        "bounties": bounties,
        "count": bounties.len(),
    }))
}

/// Get recent events for a bounty (snapshot of watch --once).
// checks: bounty_id is valid, RPC reachable
// effects: none (read-only)
// returns: collected events as JSON array
pub async fn execute_events(bounty_id: u64) -> Result<serde_json::Value> {
    let cfg = config::load_config();
    let rpc = crate::rpc::RpcClient::new(&cfg.rpc_url);
    let bounty_id_hex = format!("0x{:064x}", bounty_id);

    const LOOKBACK: u64 = 50_000;
    let current = rpc.eth_block_number().await?;
    let from_block = current.saturating_sub(LOOKBACK);

    let mut events: Vec<serde_json::Value> = Vec::new();

    // Events indexed by bountyId in topic[1]
    for (topic0, event_name) in abi::bounty_event_topics() {
        if let Ok(logs) = rpc.eth_get_logs_chunked(
            &cfg.contract, &[Some(topic0), Some(&bounty_id_hex)],
            from_block, current,
        ).await {
            for log in logs {
                events.push(serde_json::json!({
                    "event": event_name,
                    "log": log,
                }));
            }
        }
    }

    // Events indexed by bountyId in topic[2]
    for (topic0, event_name) in abi::audit_event_topics_by_bounty() {
        if let Ok(logs) = rpc.eth_get_logs_chunked(
            &cfg.contract, &[Some(topic0), None, Some(&bounty_id_hex)],
            from_block, current,
        ).await {
            for log in logs {
                events.push(serde_json::json!({
                    "event": event_name,
                    "log": log,
                }));
            }
        }
    }

    let count = events.len();
    Ok(serde_json::json!({
        "bounty_id": bounty_id,
        "events": events,
        "count": count,
        "from_block": from_block,
        "to_block": current,
    }))
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
            access,
            token,
        } => {
            let data = execute_submit(
                &repo,
                amount,
                &trigger,
                &mode,
                duration_hours,
                standing,
                installation_id,
                period_days,
                &access,
                &token,
            )
            .await?;
            output::print_success(format, "request.submit", &data);
        }
        RequestAction::Cancel { bounty_id } => {
            let data = execute_cancel(bounty_id).await?;
            output::print_success(format, "request.cancel", &data);
        }
        RequestAction::TopUp { bounty_id, amount } => {
            let data = execute_topup(bounty_id, amount).await?;
            output::print_success(format, "request.topup", &data);
        }
        RequestAction::List { all } => {
            let data = execute_list(all).await?;
            output::print_success(format, "request.list", &data);
        }
        RequestAction::Watch { bounty_id, interval, once } => {
            // WHY: streaming command outputs directly to stdout as NDJSON
            execute_watch(bounty_id, interval, once).await?;
        }
        RequestAction::Results { audit_id, key, raw } => {
            let data = execute_results(audit_id, key, raw).await?;
            output::print_success(format, "request.results", &data);
        }
        RequestAction::Dispute { audit_id } => {
            let data = execute_dispute(audit_id).await?;
            output::print_success(format, "request.dispute", &data);
        }
    }
    Ok(())
}
