use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tiny_keccak::{Hasher, Keccak};

use crate::config;

// ABI function selectors (keccak256 of signature, first 4 bytes)
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

fn selector(sig: &str) -> [u8; 4] {
    let hash = keccak256(sig.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

fn encode_uint256(value: u64) -> Vec<u8> {
    let mut buf = vec![0u8; 32];
    buf[24..32].copy_from_slice(&value.to_be_bytes());
    buf
}

fn decode_uint256(data: &[u8], offset: usize) -> u64 {
    let slice = &data[offset + 24..offset + 32];
    u64::from_be_bytes(slice.try_into().unwrap_or([0; 8]))
}

fn decode_address(data: &[u8], offset: usize) -> String {
    format!("0x{}", hex::encode(&data[offset + 12..offset + 32]))
}

fn decode_bool(data: &[u8], offset: usize) -> bool {
    data[offset + 31] != 0
}

pub fn repo_hash(owner: &str, repo: &str) -> [u8; 32] {
    keccak256(format!("github:{}/{}", owner, repo).as_bytes())
}

// JSON-RPC client for Sapphire
async fn eth_call(rpc: &str, to: &str, data: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::new();
    let resp = client
        .post(rpc)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{"to": to, "data": data}, "latest"],
            "id": 1
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let hex_result = resp["result"]
        .as_str()
        .context("No result in eth_call response")?;
    let clean = hex_result.strip_prefix("0x").unwrap_or(hex_result);
    Ok(hex::decode(clean)?)
}

async fn eth_get_balance(rpc: &str, address: &str) -> Result<u128> {
    let client = reqwest::Client::new();
    let resp = client
        .post(rpc)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [address, "latest"],
            "id": 1
        }))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let hex_result = resp["result"]
        .as_str()
        .context("No result in eth_getBalance response")?;
    let clean = hex_result.strip_prefix("0x").unwrap_or(hex_result);
    Ok(u128::from_str_radix(clean, 16).unwrap_or(0))
}

async fn eth_chain_id(rpc: &str) -> Result<u64> {
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

// Public API

#[derive(Debug, Serialize)]
pub struct Bounty {
    pub id: u64,
    pub requester: String,
    pub amount: String,
    pub amount_wei: String,
    pub standing: bool,
    pub state: String,
    pub audit_count: u64,
}

#[derive(Debug, Serialize)]
pub struct MarketStatus {
    pub contract: String,
    pub rpc: String,
    pub chain_id: u64,
    pub bounty_count: u64,
    pub audit_count: u64,
}

#[derive(Debug, Serialize)]
pub struct WalletInfo {
    pub address: String,
    pub balance_rose: String,
    pub balance_wei: String,
    pub network: String,
    pub chain_id: u64,
}

pub async fn get_bounty_count() -> Result<u64> {
    let cfg = config::load_config();
    let sel = selector("bountyCount()");
    let data = format!("0x{}", hex::encode(sel));
    let result = eth_call(&cfg.rpc_url, &cfg.contract, &data).await?;
    Ok(decode_uint256(&result, 0))
}

pub async fn get_audit_count() -> Result<u64> {
    let cfg = config::load_config();
    let sel = selector("auditCount()");
    let data = format!("0x{}", hex::encode(sel));
    let result = eth_call(&cfg.rpc_url, &cfg.contract, &data).await?;
    Ok(decode_uint256(&result, 0))
}

pub async fn get_bounty(bounty_id: u64) -> Result<Bounty> {
    let cfg = config::load_config();
    let sel = selector("getBounty(uint256)");
    let mut calldata = sel.to_vec();
    calldata.extend_from_slice(&encode_uint256(bounty_id));
    let data = format!("0x{}", hex::encode(&calldata));
    let result = eth_call(&cfg.rpc_url, &cfg.contract, &data).await?;

    if result.len() < 256 {
        anyhow::bail!("Bounty #{} not found", bounty_id);
    }

    let amount_wei = {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&result[48..64]);
        u128::from_be_bytes(bytes)
    };
    let amount_rose = amount_wei as f64 / 1e18;
    let state_num = decode_uint256(&result, 192);
    let state = match state_num {
        0 => "Open",
        1 => "Completed",
        2 => "Cancelled",
        _ => "Unknown",
    };

    Ok(Bounty {
        id: bounty_id,
        requester: decode_address(&result, 0),
        amount: format!("{:.4} ROSE", amount_rose),
        amount_wei: amount_wei.to_string(),
        standing: decode_bool(&result, 160),
        state: state.to_string(),
        audit_count: decode_uint256(&result, 224),
    })
}

pub async fn list_bounties(only_open: bool) -> Result<Vec<Bounty>> {
    let count = get_bounty_count().await?;
    let mut bounties = Vec::new();
    for i in 1..=count {
        match get_bounty(i).await {
            Ok(b) => {
                if only_open && b.state != "Open" {
                    continue;
                }
                bounties.push(b);
            }
            Err(_) => continue,
        }
    }
    Ok(bounties)
}

pub async fn get_market_status() -> Result<MarketStatus> {
    let cfg = config::load_config();
    let chain_id = eth_chain_id(&cfg.rpc_url).await.unwrap_or(0);
    let bounty_count = get_bounty_count().await.unwrap_or(0);
    let audit_count = get_audit_count().await.unwrap_or(0);

    Ok(MarketStatus {
        contract: cfg.contract,
        rpc: cfg.rpc_url,
        chain_id,
        bounty_count,
        audit_count,
    })
}

pub async fn get_wallet_info(private_key: &str) -> Result<WalletInfo> {
    let cfg = config::load_config();
    // Derive address from private key using secp256k1
    let key_bytes = hex::decode(private_key.strip_prefix("0x").unwrap_or(private_key))?;

    let secret_key = k256::ecdsa::SigningKey::from_bytes((&key_bytes[..]).into())
        .context("Invalid private key")?;
    let public_key = secret_key.verifying_key();
    let public_key_bytes = public_key.to_encoded_point(false);
    let hash = keccak256(&public_key_bytes.as_bytes()[1..]); // skip 0x04 prefix
    let address = format!("0x{}", hex::encode(&hash[12..32]));

    let chain_id = eth_chain_id(&cfg.rpc_url).await.unwrap_or(0);
    let balance_wei = eth_get_balance(&cfg.rpc_url, &address).await.unwrap_or(0);
    let balance_rose = balance_wei as f64 / 1e18;

    let network = match chain_id {
        23295 => "Sapphire Testnet",
        23294 => "Sapphire Mainnet",
        _ => "Unknown",
    };

    Ok(WalletInfo {
        address,
        balance_rose: format!("{:.4} ROSE", balance_rose),
        balance_wei: balance_wei.to_string(),
        network: network.to_string(),
        chain_id,
    })
}
