/// MCP tool definitions and dispatch.
// WHY: each CLI command maps 1:1 to an MCP tool. Streaming commands
//      (watch, performer start) are converted to snapshot tools.

use serde_json::{json, Value};

/// Return the full list of MCP tool definitions.
pub fn list_tools() -> Value {
    json!({
        "tools": [
            // === Request tools ===
            tool_def("pora_request_list", "List bounties on the security audit market. Returns all open bounties with amounts, states, and audit counts.", json!({
                "type": "object",
                "properties": {
                    "all": { "type": "boolean", "description": "Include closed/cancelled bounties. Default: false" }
                }
            })),
            tool_def("pora_request_submit", "[COSTS TOKENS] Create a new security audit bounty on the market. Deposits ROSE tokens as escrow. Returns bounty ID and transaction hashes.", json!({
                "type": "object",
                "properties": {
                    "repo": { "type": "string", "description": "Repository in owner/repo format (e.g. 'acme/api')" },
                    "amount": { "type": "number", "description": "Amount of ROSE to deposit. Default: 1.0" },
                    "trigger": { "type": "string", "description": "Trigger mode: 'on-change' or 'periodic'. Default: 'on-change'" },
                    "mode": { "type": "string", "description": "Audit mode: 'static', 'tee-local', or 'tee-api'. Default: 'tee-api'" },
                    "duration_hours": { "type": "integer", "description": "Bounty duration in hours. Default: 168 (1 week)" },
                    "standing": { "type": "boolean", "description": "Standing bounty (repeating audits from pool). Default: false" },
                    "access": { "type": "string", "description": "Repo access mode: 'auto', 'public', 'token', or 'app'. Default: 'auto'" },
                    "token": { "type": "string", "description": "GitHub PAT for private repo access (only with access='token'). WARNING: value may appear in agent conversation logs. Prefer setting GITHUB_TOKEN env var and using access='auto'" }
                },
                "required": ["repo"]
            })),
            tool_def("pora_request_cancel", "[COSTS TOKENS] Cancel a bounty and reclaim escrowed funds.", json!({
                "type": "object",
                "properties": {
                    "bounty_id": { "type": "integer", "description": "Bounty ID to cancel" }
                },
                "required": ["bounty_id"]
            })),
            tool_def("pora_request_topup", "[COSTS TOKENS] Top up a standing bounty's pool with additional ROSE tokens.", json!({
                "type": "object",
                "properties": {
                    "bounty_id": { "type": "integer", "description": "Bounty ID to top up" },
                    "amount": { "type": "number", "description": "Amount of ROSE to add" }
                },
                "required": ["bounty_id", "amount"]
            })),
            tool_def("pora_request_events", "Get recent on-chain events for a specific bounty. Returns a snapshot of audit activity (claims, submissions, payouts) from the last ~2 days.", json!({
                "type": "object",
                "properties": {
                    "bounty_id": { "type": "integer", "description": "Bounty ID to check events for" }
                },
                "required": ["bounty_id"]
            })),
            tool_def("pora_request_results", "Download and decrypt audit results for a completed audit. Requires the X25519 delivery private key.", json!({
                "type": "object",
                "properties": {
                    "audit_id": { "type": "integer", "description": "Audit ID to download results for" },
                    "key": { "type": "string", "description": "Path to X25519 private key (auto-detected from ~/.pora/keys/ if omitted)" }
                },
                "required": ["audit_id"]
            })),
            tool_def("pora_request_dispute", "[COSTS TOKENS] Dispute an audit result. Must be called by the requester within the challenge window.", json!({
                "type": "object",
                "properties": {
                    "audit_id": { "type": "integer", "description": "Audit ID to dispute" }
                },
                "required": ["audit_id"]
            })),

            // === Performer tools ===
            tool_def("pora_performer_init", "[MODIFIES STATE] Initialize performer configuration with LLM provider and API key.", json!({
                "type": "object",
                "properties": {
                    "provider": { "type": "string", "description": "LLM provider: 'anthropic', 'openai', or 'openrouter'. Default: 'anthropic'" },
                    "use_claude_login": { "type": "boolean", "description": "Auto-detect Claude Code OAuth token. Default: false" }
                }
            })),
            tool_def("pora_performer_status", "Show performer earnings, reputation score, registration status, and active jobs.", json!({
                "type": "object",
                "properties": {}
            })),
            tool_def("pora_performer_monitor", "Get recent on-chain events for this performer. Returns a snapshot of audit claims, submissions, and payouts from the last ~2 days.", json!({
                "type": "object",
                "properties": {}
            })),
            tool_def("pora_performer_claim", "[COSTS TOKENS] Claim audit payout for a completed audit. Requires the payout to be unlocked.", json!({
                "type": "object",
                "properties": {
                    "audit_id": { "type": "integer", "description": "Audit ID to claim payout for" }
                },
                "required": ["audit_id"]
            })),
            tool_def("pora_performer_release", "[COSTS TOKENS] Release a bounty claim. Allows other performers to claim the bounty.", json!({
                "type": "object",
                "properties": {
                    "bounty_id": { "type": "integer", "description": "Bounty ID to release claim for" }
                },
                "required": ["bounty_id"]
            })),
            tool_def("pora_performer_request_claim", "[MODIFIES STATE] Request a bounty claim via the 2-step TEE claim flow. Sends requestClaim on-chain, then polls for TEE confirmation (BountyClaimAcquired) or rejection (ClaimRejected). Returns when TEE responds or timeout.", json!({
                "type": "object",
                "properties": {
                    "bounty_id": { "type": "integer", "description": "Bounty ID to claim" },
                    "timeout": { "type": "integer", "description": "Max seconds to wait for TEE response. Default: 120" }
                },
                "required": ["bounty_id"]
            })),

            // === System tools ===
            tool_def("pora_system_doctor", "Check system health: config, network connectivity, wallet balance, performer registration, delivery keys.", json!({
                "type": "object",
                "properties": {}
            })),
            tool_def("pora_system_whoami", "Show current wallet address, network (chain ID), and ROSE balance.", json!({
                "type": "object",
                "properties": {}
            })),
            tool_def("pora_system_keygen", "[MODIFIES STATE] Generate X25519 delivery keypair for encrypted audit results.", json!({
                "type": "object",
                "properties": {
                    "force": { "type": "boolean", "description": "Overwrite existing keys. Default: false" }
                }
            })),
        ]
    })
}

fn tool_def(name: &str, description: &str, input_schema: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema
    })
}

/// Dispatch a tools/call request to the appropriate handler.
// checks: tool name is valid
// effects: may send on-chain transactions for write tools
// returns: MCP tool result with content array
pub async fn call_tool(params: &Value) -> anyhow::Result<Value> {
    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    let result = match name {
        "pora_request_list" => {
            let all = args.get("all").and_then(|v| v.as_bool()).unwrap_or(false);
            crate::commands::request::execute_list(all).await?
        }
        "pora_request_submit" => {
            let repo = arg_str(&args, "repo")?;
            let amount = args.get("amount").and_then(|v| v.as_f64()).unwrap_or(1.0);
            let trigger = args.get("trigger").and_then(|v| v.as_str()).unwrap_or("on-change");
            let mode = args.get("mode").and_then(|v| v.as_str()).unwrap_or("tee-api");
            let duration_hours = args.get("duration_hours").and_then(|v| v.as_u64()).unwrap_or(168);
            let standing = args.get("standing").and_then(|v| v.as_bool()).unwrap_or(false);
            let access = args.get("access").and_then(|v| v.as_str()).unwrap_or("auto");
            let token = args.get("token").and_then(|v| v.as_str()).map(String::from);
            crate::commands::request::execute_submit(
                &repo, amount, trigger, mode, duration_hours,
                standing, None, 7, access, &token,
            ).await?
        }
        "pora_request_cancel" => {
            let bounty_id = arg_u64(&args, "bounty_id")?;
            crate::commands::request::execute_cancel(bounty_id).await?
        }
        "pora_request_topup" => {
            let bounty_id = arg_u64(&args, "bounty_id")?;
            let amount = arg_f64(&args, "amount")?;
            crate::commands::request::execute_topup(bounty_id, amount).await?
        }
        "pora_request_events" => {
            let bounty_id = arg_u64(&args, "bounty_id")?;
            crate::commands::request::execute_events(bounty_id).await?
        }
        "pora_request_results" => {
            let audit_id = arg_u64(&args, "audit_id")?;
            let key = args.get("key").and_then(|v| v.as_str()).map(String::from);
            crate::commands::request::execute_results(audit_id, key, false).await?
        }
        "pora_request_dispute" => {
            let audit_id = arg_u64(&args, "audit_id")?;
            crate::commands::request::execute_dispute(audit_id).await?
        }
        "pora_performer_init" => {
            let provider = args.get("provider").and_then(|v| v.as_str()).unwrap_or("anthropic");
            let use_claude_login = args.get("use_claude_login").and_then(|v| v.as_bool()).unwrap_or(false);
            crate::commands::performer::execute_init(provider, use_claude_login)?
        }
        "pora_performer_status" => {
            crate::commands::performer::execute_status().await?
        }
        "pora_performer_monitor" => {
            // WHY: snapshot version of performer start --once
            // Reuses the same event fetching logic but returns collected events
            crate::commands::performer::execute_monitor().await?
        }
        "pora_performer_claim" => {
            let audit_id = arg_u64(&args, "audit_id")?;
            crate::commands::performer::execute_claim_payout(audit_id).await?
        }
        "pora_performer_release" => {
            let bounty_id = arg_u64(&args, "bounty_id")?;
            crate::commands::performer::execute_release_claim(bounty_id).await?
        }
        "pora_performer_request_claim" => {
            let bounty_id = arg_u64(&args, "bounty_id")?;
            let timeout = args.get("timeout").and_then(|v| v.as_u64()).unwrap_or(120);
            crate::commands::performer::execute_claim(bounty_id, timeout).await?
        }
        "pora_system_doctor" => {
            crate::commands::system::execute_doctor().await?
        }
        "pora_system_whoami" => {
            crate::commands::system::execute_whoami().await?
        }
        "pora_system_keygen" => {
            let force = args.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
            crate::commands::system::execute_keygen(force)?
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown tool: {}", name));
        }
    };

    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&result)?
        }]
    }))
}

fn arg_str(args: &Value, key: &str) -> anyhow::Result<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| anyhow::anyhow!("Missing required argument: {}", key))
}

fn arg_u64(args: &Value, key: &str) -> anyhow::Result<u64> {
    args.get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Missing required argument: {}", key))
}

fn arg_f64(args: &Value, key: &str) -> anyhow::Result<f64> {
    args.get(key)
        .and_then(|v| v.as_f64())
        .ok_or_else(|| anyhow::anyhow!("Missing required argument: {}", key))
}
