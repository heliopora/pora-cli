use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::abi;
use crate::output;

/// JSON-RPC client for Ethereum/Sapphire read operations (getLogs, call, blockNumber).
// WHY: separate from contract.rs which handles write-path (tx signing).
//      This module serves the read-only streaming commands (watch, performer start).
pub struct RpcClient {
    url: String,
    client: reqwest::Client,
}

impl RpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: reqwest::Client::new(),
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });
        let resp = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .context("RPC transport error")?;
        let json: Value = resp.json().await.context("RPC response parse error")?;
        if let Some(err) = json.get("error") {
            bail!("RPC node error: {}", err);
        }
        json.get("result")
            .cloned()
            .context("missing result field in RPC response")
    }

    /// Execute a read-only contract call.
    pub async fn eth_call(&self, to: &str, data: &str) -> Result<String> {
        let result = self
            .call("eth_call", json!([{"to": to, "data": data}, "latest"]))
            .await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .context("eth_call returned non-string")
    }

    /// Fetch event logs matching a filter.
    pub async fn eth_get_logs(
        &self,
        address: &str,
        topics: &[Option<&str>],
        from_block: &str,
        to_block: &str,
    ) -> Result<Vec<Value>> {
        let topics_json: Vec<Value> = topics
            .iter()
            .map(|t| match t {
                Some(s) => Value::String((*s).to_string()),
                None => Value::Null,
            })
            .collect();
        let filter = json!({
            "address": address,
            "topics": topics_json,
            "fromBlock": from_block,
            "toBlock": to_block,
        });
        let result = self.call("eth_getLogs", json!([filter])).await?;
        result
            .as_array()
            .cloned()
            .context("eth_getLogs returned non-array")
    }

    /// Get the latest block number.
    pub async fn eth_block_number(&self) -> Result<u64> {
        let result = self.call("eth_blockNumber", json!([])).await?;
        let hex = result.as_str().context("blockNumber non-string")?;
        u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .context("invalid blockNumber hex")
    }

    /// Fetch logs, decode each with abi::decode_event, and emit as NDJSON.
    /// Emits error events on failure instead of propagating.
    pub async fn fetch_and_emit_logs(
        &self,
        address: &str,
        topics: &[Option<&str>],
        from_block: &str,
        to_block: &str,
        event_name: &str,
    ) {
        match self.eth_get_logs(address, topics, from_block, to_block).await {
            Ok(logs) => {
                for log in &logs {
                    output::ndjson_event(abi::decode_event(event_name, log));
                }
            }
            Err(e) => {
                output::ndjson_event(json!({
                    "event": "error",
                    "message": format!("getLogs({}): {}", event_name, e),
                }));
            }
        }
    }
}
