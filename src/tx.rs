use anyhow::{Context, Result};
use k256::ecdsa::SigningKey;
use serde_json::json;

use crate::config;
use crate::crypto::keccak256;

// --- RLP encoding (EIP-155 legacy transactions) ---

// checks: none
// effects: none
// returns: RLP-encoded single byte string
// WHY: manual RLP for the tx envelope avoids pulling in the full alloy provider stack.
//      Legacy (type 0) transactions are sufficient for Oasis Sapphire.
fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        vec![data[0]]
    } else if data.len() < 56 {
        let mut out = vec![0x80 + data.len() as u8];
        out.extend_from_slice(data);
        out
    } else {
        let len_bytes = to_minimal_be(&(data.len() as u64).to_be_bytes());
        let mut out = vec![0xb7 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(data);
        out
    }
}

// checks: none
// effects: none
// returns: RLP list wrapping the concatenated items
fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for item in items {
        payload.extend_from_slice(item);
    }
    if payload.len() < 56 {
        let mut out = vec![0xc0 + payload.len() as u8];
        out.extend_from_slice(&payload);
        out
    } else {
        let len_bytes = to_minimal_be(&(payload.len() as u64).to_be_bytes());
        let mut out = vec![0xf7 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(&payload);
        out
    }
}

// checks: none
// effects: none
// returns: big-endian encoding with leading zeros stripped
fn to_minimal_be(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

fn rlp_encode_u64(value: u64) -> Vec<u8> {
    rlp_encode_bytes(&to_minimal_be(&value.to_be_bytes()))
}

fn rlp_encode_u128(value: u128) -> Vec<u8> {
    rlp_encode_bytes(&to_minimal_be(&value.to_be_bytes()))
}

/// EIP-155 legacy transaction (type 0).
/// WHY: Oasis Sapphire supports legacy transactions. Using type 0 avoids
///      EIP-1559 fee market complexity that Sapphire doesn't require.
pub struct LegacyTx {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
    pub chain_id: u64,
}

impl LegacyTx {
    // checks: none
    // effects: none
    // returns: RLP-encoded unsigned tx for EIP-155 signing (includes chain_id, 0, 0)
    fn rlp_for_signing(&self) -> Vec<u8> {
        let items = vec![
            rlp_encode_u64(self.nonce),
            rlp_encode_u128(self.gas_price),
            rlp_encode_u64(self.gas_limit),
            rlp_encode_bytes(&self.to),
            rlp_encode_u128(self.value),
            rlp_encode_bytes(&self.data),
            rlp_encode_u64(self.chain_id),
            rlp_encode_bytes(&[]),  // EIP-155: empty r
            rlp_encode_bytes(&[]),  // EIP-155: empty s
        ];
        rlp_encode_list(&items)
    }

    // checks: none
    // effects: none
    // returns: keccak256 hash of RLP-encoded unsigned tx
    fn signing_hash(&self) -> [u8; 32] {
        keccak256(&self.rlp_for_signing())
    }

    // checks: signing_key is valid secp256k1 key
    // effects: none
    // returns: RLP-encoded signed transaction ready for eth_sendRawTransaction
    // SECURITY: EIP-155 replay protection via chain_id in v value
    fn sign(&self, signing_key: &SigningKey) -> Result<Vec<u8>> {
        let hash = self.signing_hash();
        let (sig, recid) = signing_key
            .sign_prehash_recoverable(&hash)
            .context("Failed to sign transaction")?;
        let sig_bytes = sig.to_bytes();
        let r = &sig_bytes[..32];
        let s = &sig_bytes[32..64];

        // EIP-155: v = recid + 35 + 2 * chain_id
        let v = recid.to_byte() as u64 + 35 + 2 * self.chain_id;

        let items = vec![
            rlp_encode_u64(self.nonce),
            rlp_encode_u128(self.gas_price),
            rlp_encode_u64(self.gas_limit),
            rlp_encode_bytes(&self.to),
            rlp_encode_u128(self.value),
            rlp_encode_bytes(&self.data),
            rlp_encode_u64(v),
            rlp_encode_bytes(trim_leading_zeros(r)),
            rlp_encode_bytes(trim_leading_zeros(s)),
        ];
        Ok(rlp_encode_list(&items))
    }
}

// checks: none
// effects: none
// returns: byte slice with leading zeros removed
fn trim_leading_zeros(data: &[u8]) -> &[u8] {
    let start = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    if start == data.len() {
        &data[..0]
    } else {
        &data[start..]
    }
}

// checks: hex_addr is valid 0x-prefixed 20-byte address
// effects: none
// returns: 20-byte address array
fn parse_address(hex_addr: &str) -> Result<[u8; 20]> {
    let clean = hex_addr.strip_prefix("0x").unwrap_or(hex_addr);
    let bytes = hex::decode(clean).context("Invalid address hex")?;
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

// --- JSON-RPC helpers ---

// checks: rpc is valid URL, address is 0x-prefixed
// effects: HTTP POST to RPC
// returns: current nonce for address
async fn eth_get_transaction_count(rpc: &str, address: &str) -> Result<u64> {
    let client = reqwest::Client::new();
    let resp = client
        .post(rpc)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [address, "pending"],
            "id": 1
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let hex_result = resp["result"]
        .as_str()
        .context("No result in eth_getTransactionCount response")?;
    let clean = hex_result.strip_prefix("0x").unwrap_or(hex_result);
    Ok(u64::from_str_radix(clean, 16).unwrap_or(0))
}

// checks: rpc is valid URL
// effects: HTTP POST to RPC
// returns: current gas price in wei
async fn eth_gas_price(rpc: &str) -> Result<u128> {
    let client = reqwest::Client::new();
    let resp = client
        .post(rpc)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_gasPrice",
            "params": [],
            "id": 1
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let hex_result = resp["result"]
        .as_str()
        .context("No result in eth_gasPrice response")?;
    let clean = hex_result.strip_prefix("0x").unwrap_or(hex_result);
    Ok(u128::from_str_radix(clean, 16).unwrap_or(100_000_000_000))
}

// checks: rpc is valid URL, raw_tx is RLP-encoded signed tx
// effects: submits transaction to network
// returns: transaction hash
async fn eth_send_raw_transaction(rpc: &str, raw_tx: &[u8]) -> Result<String> {
    let client = reqwest::Client::new();
    let tx_hex = format!("0x{}", hex::encode(raw_tx));
    let resp = client
        .post(rpc)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [tx_hex],
            "id": 1
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    if let Some(err) = resp.get("error") {
        let msg = err["message"].as_str().unwrap_or("unknown RPC error");
        anyhow::bail!("eth_sendRawTransaction failed: {}", msg);
    }

    resp["result"]
        .as_str()
        .map(|s| s.to_string())
        .context("No result in eth_sendRawTransaction response")
}

/// Transaction receipt from eth_getTransactionReceipt.
#[derive(Debug)]
pub struct TxReceipt {
    pub tx_hash: String,
    pub status: bool,
    pub block_number: u64,
    pub gas_used: u64,
    pub logs: Vec<serde_json::Value>,
}

// checks: rpc is valid URL, tx_hash is 0x-prefixed
// effects: polls RPC until receipt is available (max 60 attempts, 2s interval)
// returns: transaction receipt
// WHY: Sapphire block time is ~6s, so 60 attempts × 2s = 2 min timeout is generous.
pub async fn wait_for_receipt(rpc: &str, tx_hash: &str) -> Result<TxReceipt> {
    let client = reqwest::Client::new();

    for _ in 0..60 {
        let resp = client
            .post(rpc)
            .json(&json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash],
                "id": 1
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        if resp["result"].is_null() {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            continue;
        }

        let receipt = &resp["result"];
        let status_hex = receipt["status"].as_str().unwrap_or("0x0");
        let status = status_hex == "0x1";
        let block_hex = receipt["blockNumber"].as_str().unwrap_or("0x0");
        let block_clean = block_hex.strip_prefix("0x").unwrap_or(block_hex);
        let gas_hex = receipt["gasUsed"].as_str().unwrap_or("0x0");
        let gas_clean = gas_hex.strip_prefix("0x").unwrap_or(gas_hex);

        return Ok(TxReceipt {
            tx_hash: tx_hash.to_string(),
            status,
            block_number: u64::from_str_radix(block_clean, 16).unwrap_or(0),
            gas_used: u64::from_str_radix(gas_clean, 16).unwrap_or(0),
            logs: receipt["logs"].as_array().cloned().unwrap_or_default(),
        });
    }

    anyhow::bail!("Transaction receipt not found after 120 seconds: {}", tx_hash)
}

/// Derive Ethereum address from a private key.
// checks: private_key is valid hex (with or without 0x prefix)
// effects: none
// returns: 0x-prefixed checksumless Ethereum address
pub fn derive_address(private_key: &str) -> Result<String> {
    let key_bytes = hex::decode(private_key.strip_prefix("0x").unwrap_or(private_key))?;
    let signing_key =
        SigningKey::from_bytes((&key_bytes[..]).into()).context("Invalid private key")?;
    let public_key = signing_key.verifying_key();
    let public_key_bytes = public_key.to_encoded_point(false);
    let hash = keccak256(&public_key_bytes.as_bytes()[1..]); // skip 0x04 prefix
    Ok(format!("0x{}", hex::encode(&hash[12..32])))
}

/// Build, sign, and send a transaction. Returns the tx hash.
// checks: private key is configured, RPC is reachable
// effects: sends a signed transaction to the network
// returns: transaction hash string
pub async fn send_transaction(
    to: &str,
    value: u128,
    data: Vec<u8>,
    gas_limit: u64,
) -> Result<String> {
    let cfg = config::load_config();
    let private_key = config::get_private_key()?;
    let address = derive_address(&private_key)?;

    let key_bytes =
        hex::decode(private_key.strip_prefix("0x").unwrap_or(&private_key))?;
    let signing_key =
        SigningKey::from_bytes((&key_bytes[..]).into()).context("Invalid private key")?;

    let chain_id = get_chain_id(&cfg.rpc_url).await?;
    let nonce = eth_get_transaction_count(&cfg.rpc_url, &address).await?;
    let gas_price = eth_gas_price(&cfg.rpc_url).await?;

    let tx = LegacyTx {
        nonce,
        gas_price,
        gas_limit,
        to: parse_address(to)?,
        value,
        data,
        chain_id,
    };

    let signed = tx.sign(&signing_key)?;
    eth_send_raw_transaction(&cfg.rpc_url, &signed).await
}

/// Send a transaction and wait for its receipt.
// checks: same as send_transaction
// effects: sends tx and polls for receipt
// returns: (tx_hash, receipt)
pub async fn send_and_confirm(
    to: &str,
    value: u128,
    data: Vec<u8>,
    gas_limit: u64,
) -> Result<(String, TxReceipt)> {
    let rpc_url = config::load_config().rpc_url;
    let tx_hash = send_transaction(to, value, data, gas_limit).await?;
    let receipt = wait_for_receipt(&rpc_url, &tx_hash).await?;
    if !receipt.status {
        anyhow::bail!(
            "Transaction reverted: {} (gas used: {})",
            tx_hash,
            receipt.gas_used
        );
    }
    Ok((tx_hash, receipt))
}

// checks: rpc is valid URL
// effects: HTTP POST
// returns: chain ID
async fn get_chain_id(rpc: &str) -> Result<u64> {
    let client = reqwest::Client::new();
    let resp = client
        .post(rpc)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_chainId",
            "params": [],
            "id": 1
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let hex_result = resp["result"]
        .as_str()
        .context("No result in eth_chainId response")?;
    let clean = hex_result.strip_prefix("0x").unwrap_or(hex_result);
    Ok(u64::from_str_radix(clean, 16).unwrap_or(0))
}
