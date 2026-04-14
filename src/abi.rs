use std::sync::LazyLock;

use serde_json::{json, Value};

use crate::crypto::{keccak256, selector};

// --- ABI encoding primitives ---

// checks: none
// effects: none
// returns: 32-byte ABI-encoded uint256
pub fn encode_uint256(value: u64) -> Vec<u8> {
    let mut buf = vec![0u8; 32];
    buf[24..32].copy_from_slice(&value.to_be_bytes());
    buf
}

// checks: none
// effects: none
// returns: 32-byte ABI-encoded bool
fn encode_bool(value: bool) -> Vec<u8> {
    let mut buf = vec![0u8; 32];
    if value {
        buf[31] = 1;
    }
    buf
}

// checks: none
// effects: none
// returns: 32-byte ABI-encoded uint8 (left-padded)
fn encode_uint8(value: u8) -> Vec<u8> {
    let mut buf = vec![0u8; 32];
    buf[31] = value;
    buf
}

/// ABI-encode an Ethereum address as 32 bytes (12 zero bytes + 20 address bytes).
// checks: address_hex is 40 hex chars (with or without 0x prefix)
// effects: none
// returns: 32-byte left-padded address
pub fn encode_address(address_hex: &str) -> Vec<u8> {
    let clean = address_hex.trim_start_matches("0x").to_lowercase();
    assert_eq!(clean.len(), 40, "address must be 40 hex chars, got {}", clean.len());
    let addr_bytes = hex::decode(&clean).expect("invalid address hex");
    let mut buf = vec![0u8; 12];
    buf.extend_from_slice(&addr_bytes);
    buf
}

// checks: none
// effects: none
// returns: ABI-encoded dynamic string (offset is handled by caller)
// WHY: ABI dynamic types store: offset → (length, padded data).
//      The offset is relative to the start of the params block.
fn encode_string_data(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut data = encode_uint256(bytes.len() as u64); // length prefix
    data.extend_from_slice(bytes);
    // pad to 32-byte boundary
    let pad = (32 - (bytes.len() % 32)) % 32;
    data.extend(vec![0u8; pad]);
    data
}

/// Compute keccak256(abi.encodePacked("github:", owner, "/", repo)).
/// This matches the contract's repoHash calculation.
// checks: owner and repo are non-empty
// effects: none
// returns: 32-byte hash matching LetheMarket.sol repoHash
pub fn repo_hash(owner: &str, repo: &str) -> [u8; 32] {
    keccak256(format!("github:{}/{}", owner, repo).as_bytes())
}

/// Encode createBounty(bytes32 _repoHash, uint256 _duration, bool _standing)
// checks: repo_hash is 32 bytes
// effects: none
// returns: calldata for createBounty
pub fn encode_create_bounty(repo_hash: &[u8; 32], duration_secs: u64, standing: bool) -> Vec<u8> {
    let mut data = selector("createBounty(bytes32,uint256,bool)").to_vec();
    data.extend_from_slice(repo_hash);           // bytes32 _repoHash
    data.extend(encode_uint256(duration_secs));   // uint256 _duration
    data.extend(encode_bool(standing));           // bool _standing
    data
}

/// Encode setRepoInfo(uint256 _bountyId, string _owner, string _repo, uint256 _installationId)
/// WHY: this function has dynamic types (string), so we use offset-based ABI encoding.
// checks: none
// effects: none
// returns: calldata for setRepoInfo with correct dynamic offsets
pub fn encode_set_repo_info(
    bounty_id: u64,
    owner: &str,
    repo: &str,
    installation_id: u64,
) -> Vec<u8> {
    let mut data = selector("setRepoInfo(uint256,string,string,uint256)").to_vec();

    // Head section: 4 slots (each 32 bytes)
    // slot 0: _bountyId (static)
    // slot 1: offset to _owner string data
    // slot 2: offset to _repo string data
    // slot 3: _installationId (static)
    let head_size: u64 = 4 * 32; // 128 bytes

    let owner_data = encode_string_data(owner);
    let repo_data = encode_string_data(repo);

    let owner_offset = head_size;
    let repo_offset = head_size + owner_data.len() as u64;

    data.extend(encode_uint256(bounty_id));         // slot 0
    data.extend(encode_uint256(owner_offset));       // slot 1: offset to owner
    data.extend(encode_uint256(repo_offset));        // slot 2: offset to repo
    data.extend(encode_uint256(installation_id));    // slot 3

    // Tail: dynamic data
    data.extend(owner_data);
    data.extend(repo_data);

    data
}

/// Encode setAuditConfig(uint256 _bountyId, uint8 _triggerMode, uint8 _scopeMode, uint8 _toolMode, uint256 _periodDays)
// checks: trigger_mode and tool_mode are valid
// effects: none
// returns: calldata for setAuditConfig
pub fn encode_set_audit_config(
    bounty_id: u64,
    trigger_mode: u8,
    scope_mode: u8,
    tool_mode: u8,
    period_days: u64,
) -> Vec<u8> {
    let mut data =
        selector("setAuditConfig(uint256,uint8,uint8,uint8,uint256)").to_vec();
    data.extend(encode_uint256(bounty_id));
    data.extend(encode_uint8(trigger_mode));
    data.extend(encode_uint8(scope_mode));
    data.extend(encode_uint8(tool_mode));
    data.extend(encode_uint256(period_days));
    data
}

/// Encode setDeliveryConfig(uint256 _bountyId, bytes32 _encryptionPubKey, bytes32 _notificationPolicyHash, uint8 _deliveryMode)
/// WHY: DeliveryMode is an enum in Solidity, encoded as uint8 in ABI.
// checks: none
// effects: none
// returns: calldata for setDeliveryConfig
pub fn encode_set_delivery_config(
    bounty_id: u64,
    encryption_pub_key: &[u8; 32],
    notification_policy_hash: &[u8; 32],
    delivery_mode: u8,
) -> Vec<u8> {
    let mut data =
        selector("setDeliveryConfig(uint256,bytes32,bytes32,uint8)").to_vec();
    data.extend(encode_uint256(bounty_id));
    data.extend_from_slice(encryption_pub_key);
    data.extend_from_slice(notification_policy_hash);
    data.extend(encode_uint8(delivery_mode));
    data
}

/// Encode cancelBounty(uint256 _bountyId)
// checks: none
// effects: none
// returns: calldata for cancelBounty
pub fn encode_cancel_bounty(bounty_id: u64) -> Vec<u8> {
    let mut data = selector("cancelBounty(uint256)").to_vec();
    data.extend(encode_uint256(bounty_id));
    data
}

/// Encode topUpBounty(uint256 _bountyId) — payable, amount sent as tx value
// checks: none
// effects: none
// returns: calldata for topUpBounty
pub fn encode_top_up_bounty(bounty_id: u64) -> Vec<u8> {
    let mut data = selector("topUpBounty(uint256)").to_vec();
    data.extend(encode_uint256(bounty_id));
    data
}

/// Encode disputeAudit(uint256 _auditId, bytes32) — second param is unused (bytes32(0))
// checks: none
// effects: none
// returns: calldata for disputeAudit
// WHY: Solidity signature is disputeAudit(uint256,bytes32) — the bytes32 is a future-proof
//      slot, currently unused. We pass 0x00...00.
pub fn encode_dispute_audit(audit_id: u64) -> Vec<u8> {
    let mut data = selector("disputeAudit(uint256,bytes32)").to_vec();
    data.extend(encode_uint256(audit_id));
    data.extend(vec![0u8; 32]); // bytes32(0) — unused param
    data
}

/// Encode releaseBountyClaim(uint256 _bountyId)
// checks: none
// effects: none
// returns: calldata for releaseBountyClaim
pub fn encode_release_bounty_claim(bounty_id: u64) -> Vec<u8> {
    let mut data = selector("releaseBountyClaim(uint256)").to_vec();
    data.extend(encode_uint256(bounty_id));
    data
}

/// Encode claimAuditPayout(uint256 _auditId)
// checks: none
// effects: none
// returns: calldata for claimAuditPayout
pub fn encode_claim_audit_payout(audit_id: u64) -> Vec<u8> {
    let mut data = selector("claimAuditPayout(uint256)").to_vec();
    data.extend(encode_uint256(audit_id));
    data
}

/// Encode requestClaim(uint256 _bountyId, bytes32 _configHash)
// checks: config_hash is 32 bytes
// effects: none
// returns: calldata for requestClaim — the local (non-TEE) half of the 2-step claim flow
// WHY: performer's local CLI calls this to signal intent. TEE verifies configHash
//      and confirms via claimBounty.
pub fn encode_request_claim(bounty_id: u64, config_hash: &[u8; 32]) -> Vec<u8> {
    let mut data = selector("requestClaim(uint256,bytes32)").to_vec();
    data.extend(encode_uint256(bounty_id));
    data.extend_from_slice(config_hash);
    data
}

/// Encode registeredPerformers(address) — public mapping auto-getter on LetheMarket.
// checks: none
// effects: none
// returns: calldata for registeredPerformers view call (target: LetheMarket contract)
// WHY: distinct from encode_get_performer which uses getPerformer(address) — a function
//      on ReputationRegistry, not LetheMarket.
pub fn encode_is_registered_performer(address: &str) -> String {
    let sel = &keccak256(b"registeredPerformers(address)")[..4];
    let addr_clean = address.trim_start_matches("0x").to_lowercase();
    format!("0x{}{:0>64}", hex::encode(sel), addr_clean)
}

/// Encode getPerformer(address) — view call on ReputationRegistry.
// checks: none
// effects: none
// returns: calldata for getPerformer view call (target: ReputationRegistry contract)
// WHY: this returns (score, totalAudits, successCount, failStreak, status, registeredAt).
//      Must be called against reputation_registry address, NOT the main LetheMarket contract.
pub fn encode_get_reputation(address: &str) -> String {
    let sel = &keccak256(b"getPerformer(address)")[..4];
    let addr_clean = address.trim_start_matches("0x").to_lowercase();
    format!("0x{}{:0>64}", hex::encode(sel), addr_clean)
}

// ============================================================
// Event decoding + view call encoding (for watch/results/performer start)
// ============================================================

fn event_topic(signature: &str) -> String {
    format!("0x{}", hex::encode(keccak256(signature.as_bytes())))
}

// WHY: keccak256 of constant strings never changes. Compute once, reuse on every poll tick.
static BOUNTY_CREATED: LazyLock<String> =
    LazyLock::new(|| event_topic("BountyCreated(uint256,address,uint256,bool)"));
static BOUNTY_TOPUP: LazyLock<String> =
    LazyLock::new(|| event_topic("BountyTopUp(uint256,uint256,uint256)"));
static BOUNTY_CANCELLED: LazyLock<String> =
    LazyLock::new(|| event_topic("BountyCancelled(uint256)"));
static AUDIT_SUBMITTED: LazyLock<String> =
    LazyLock::new(|| event_topic("AuditSubmitted(uint256,uint256,uint8,uint256)"));
static AUDIT_RESULT_SUBMITTED: LazyLock<String> = LazyLock::new(|| {
    event_topic("AuditResultSubmitted(uint256,uint256,uint8,uint8,uint8,uint256,uint256,uint256,uint256)")
});
static AUDIT_PAYOUT_CLAIMED: LazyLock<String> =
    LazyLock::new(|| event_topic("AuditPayoutClaimed(uint256,address,uint256)"));
static AUDIT_DELIVERY_RECORDED: LazyLock<String> =
    LazyLock::new(|| event_topic("AuditDeliveryRecorded(uint256,uint8,uint8,bytes32,bytes32)"));

// TEE 2-step claim flow events
static CLAIM_REQUESTED: LazyLock<String> =
    LazyLock::new(|| event_topic("ClaimRequested(uint256,address,bytes32)"));
static BOUNTY_CLAIM_ACQUIRED: LazyLock<String> =
    LazyLock::new(|| event_topic("BountyClaimAcquired(uint256,address)"));
static CLAIM_REJECTED: LazyLock<String> =
    LazyLock::new(|| event_topic("ClaimRejected(uint256,address,bytes32)"));

/// Events indexed by bountyId in topic[1].
pub fn bounty_event_topics() -> Vec<(&'static str, &'static str)> {
    vec![
        (&BOUNTY_CREATED, "bounty.created"),
        (&BOUNTY_TOPUP, "bounty.topup"),
        (&BOUNTY_CANCELLED, "bounty.cancelled"),
    ]
}

/// Events indexed by bountyId in topic[2].
// WHY: AuditSubmitted/AuditResultSubmitted index bountyId as the SECOND indexed param.
pub fn audit_event_topics_by_bounty() -> Vec<(&'static str, &'static str)> {
    vec![
        (&AUDIT_SUBMITTED, "audit.submitted"),
        (&AUDIT_RESULT_SUBMITTED, "audit.result_submitted"),
    ]
}

pub fn audit_submitted_topic() -> &'static str { &AUDIT_SUBMITTED }
pub fn audit_result_submitted_topic() -> &'static str { &AUDIT_RESULT_SUBMITTED }
pub fn audit_payout_claimed_topic() -> &'static str { &AUDIT_PAYOUT_CLAIMED }
pub fn audit_delivery_recorded_topic() -> &'static str { &AUDIT_DELIVERY_RECORDED }
pub fn claim_requested_topic() -> &'static str { &CLAIM_REQUESTED }
pub fn bounty_claim_acquired_topic() -> &'static str { &BOUNTY_CLAIM_ACQUIRED }
pub fn claim_rejected_topic() -> &'static str { &CLAIM_REJECTED }

/// Decode a log entry into a NDJSON-ready event object.
pub fn decode_event(event_name: &str, log: &Value) -> Value {
    let topics: Vec<String> = log["topics"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|t| t.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let data = log["data"].as_str().unwrap_or("0x");
    let block_hex = log["blockNumber"].as_str().unwrap_or("0x0");
    let block = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16).unwrap_or(0);
    let tx_hash = log["transactionHash"].as_str().unwrap_or("");

    let mut event = json!({ "event": event_name, "block": block, "tx": tx_hash });

    match event_name {
        "bounty.created" => {
            if topics.len() >= 3 {
                event["bounty_id"] = json!(topic_to_u64(&topics[1]));
                event["requester"] = json!(topic_to_address(&topics[2]));
            }
            let decoded = decode_data(data);
            if decoded.len() >= 2 {
                event["amount"] = json!(hex_to_decimal_string(&decoded[0]));
                event["standing"] = json!(!is_zero_hex(&decoded[1]));
            }
        }
        "bounty.topup" => {
            if topics.len() >= 2 { event["bounty_id"] = json!(topic_to_u64(&topics[1])); }
            let decoded = decode_data(data);
            if decoded.len() >= 2 {
                event["added_amount"] = json!(hex_to_decimal_string(&decoded[0]));
                event["new_total"] = json!(hex_to_decimal_string(&decoded[1]));
            }
        }
        "bounty.cancelled" => {
            if topics.len() >= 2 { event["bounty_id"] = json!(topic_to_u64(&topics[1])); }
        }
        "audit.submitted" => {
            if topics.len() >= 3 {
                event["audit_id"] = json!(topic_to_u64(&topics[1]));
                event["bounty_id"] = json!(topic_to_u64(&topics[2]));
            }
            let decoded = decode_data(data);
            if decoded.len() >= 2 {
                event["result"] = json!(hex_to_u8(&decoded[0]));
                event["finding_count"] = json!(topic_to_u64(&decoded[1]));
            }
        }
        "payout.claimed" => {
            if topics.len() >= 3 {
                event["audit_id"] = json!(topic_to_u64(&topics[1]));
                event["performer"] = json!(topic_to_address(&topics[2]));
            }
            let decoded = decode_data(data);
            if !decoded.is_empty() {
                event["amount"] = json!(hex_to_decimal_string(&decoded[0]));
            }
        }
        "audit.result_submitted" => {
            if topics.len() >= 3 {
                event["audit_id"] = json!(topic_to_u64(&topics[1]));
                event["bounty_id"] = json!(topic_to_u64(&topics[2]));
            }
            let decoded = decode_data(data);
            if decoded.len() >= 7 {
                event["execution_outcome"] = json!(hex_to_u8(&decoded[0]));
                event["finding_outcome"] = json!(hex_to_u8(&decoded[1]));
                event["remediation_outcome"] = json!(hex_to_u8(&decoded[2]));
                event["finding_count"] = json!(topic_to_u64(&decoded[3]));
                event["execution_fee"] = json!(hex_to_decimal_string(&decoded[4]));
                event["locked_bonus_total"] = json!(hex_to_decimal_string(&decoded[5]));
                event["locked_until"] = json!(topic_to_u64(&decoded[6]));
            }
        }
        "audit.delivery_recorded" => {
            if topics.len() >= 2 { event["audit_id"] = json!(topic_to_u64(&topics[1])); }
            let decoded = decode_data(data);
            if decoded.len() >= 4 {
                event["delivery_mode"] = json!(hex_to_u8(&decoded[0]));
                event["delivery_status"] = json!(hex_to_u8(&decoded[1]));
                event["ciphertext_hash"] = json!(format!("0x{}", &decoded[2]));
                event["manifest_hash"] = json!(format!("0x{}", &decoded[3]));
            }
        }
        "claim.requested" => {
            if topics.len() >= 3 {
                event["bounty_id"] = json!(topic_to_u64(&topics[1]));
                event["performer"] = json!(topic_to_address(&topics[2]));
            }
            let decoded = decode_data(data);
            if !decoded.is_empty() {
                event["config_hash"] = json!(format!("0x{}", &decoded[0]));
            }
        }
        "claim.acquired" => {
            if topics.len() >= 3 {
                event["bounty_id"] = json!(topic_to_u64(&topics[1]));
                event["performer"] = json!(topic_to_address(&topics[2]));
            }
        }
        "claim.rejected" => {
            if topics.len() >= 3 {
                event["bounty_id"] = json!(topic_to_u64(&topics[1]));
                event["performer"] = json!(topic_to_address(&topics[2]));
            }
            let decoded = decode_data(data);
            if !decoded.is_empty() {
                event["reason"] = json!(format!("0x{}", &decoded[0]));
            }
        }
        _ => {
            event["topics"] = json!(topics);
            event["data"] = json!(data);
        }
    }
    event
}

// --- View Call Encoding ---

pub fn encode_get_audit_delivery(audit_id: u64) -> String {
    let sel = &keccak256(b"getAuditDelivery(uint256)")[..4];
    format!("0x{}{:064x}", hex::encode(sel), audit_id)
}

pub fn encode_get_audit(audit_id: u64) -> String {
    let sel = &keccak256(b"getAudit(uint256)")[..4];
    format!("0x{}{:064x}", hex::encode(sel), audit_id)
}

pub fn encode_get_delivery_config(bounty_id: u64) -> String {
    let sel = &keccak256(b"getDeliveryConfig(uint256)")[..4];
    format!("0x{}{:064x}", hex::encode(sel), bounty_id)
}

/// Encode getPendingClaim(uint256 _bountyId, address _performer) view call.
// checks: none
// effects: none
// returns: calldata for getPendingClaim — polls claim state during 2-step flow
pub fn encode_get_pending_claim(bounty_id: u64, performer_address: &str) -> String {
    let sel = &keccak256(b"getPendingClaim(uint256,address)")[..4];
    let addr_bytes = encode_address(performer_address);
    format!("0x{}{:064x}{}", hex::encode(sel), bounty_id, hex::encode(addr_bytes))
}

// --- View Call Decoding ---

pub struct AuditDeliveryInfo {
    pub ciphertext_hash: String,
    pub manifest_hash: String,
}

pub fn decode_audit_delivery(hex_data: &str) -> Option<AuditDeliveryInfo> {
    let data = hex_data.trim_start_matches("0x");
    if data.len() < 256 { return None; }
    let ciphertext_hash = format!("0x{}", &data[0..64]);
    let manifest_hash = format!("0x{}", &data[64..128]);
    if is_zero_hex(&data[0..64]) && is_zero_hex(&data[64..128]) { return None; }
    Some(AuditDeliveryInfo { ciphertext_hash, manifest_hash })
}

pub fn decode_audit_bounty_id(hex_data: &str) -> Option<u64> {
    let data = hex_data.trim_start_matches("0x");
    if data.len() < 64 { return None; }
    let trimmed = data[0..64].trim_start_matches('0');
    if trimmed.is_empty() { return Some(0); }
    u64::from_str_radix(trimmed, 16).ok()
}

pub fn decode_delivery_config_pubkey(hex_data: &str) -> Option<String> {
    let data = hex_data.trim_start_matches("0x");
    if data.len() < 64 { return None; }
    let pubkey = &data[0..64];
    if is_zero_hex(pubkey) { return None; }
    Some(format!("0x{}", pubkey))
}

pub fn is_zero_result(hex_data: &str) -> bool {
    let data = hex_data.trim_start_matches("0x");
    data.is_empty() || data.chars().all(|c| c == '0')
}

// --- Decode Helpers ---

fn decode_data(data: &str) -> Vec<String> {
    let data = data.trim_start_matches("0x");
    data.as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or("").to_string())
        .collect()
}

fn topic_to_u64(topic: &str) -> u64 {
    let hex = topic.trim_start_matches("0x");
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() { return 0; }
    u64::from_str_radix(trimmed, 16).unwrap_or(0)
}

fn topic_to_address(topic: &str) -> String {
    let hex = topic.trim_start_matches("0x");
    if hex.len() >= 40 {
        format!("0x{}", &hex[hex.len() - 40..])
    } else {
        format!("0x{}", hex)
    }
}

pub fn hex_to_decimal_string(hex: &str) -> String {
    // WHY: amounts in wei can exceed u64. u128 covers up to ~3.4e38.
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() { return "0".to_string(); }
    u128::from_str_radix(trimmed, 16)
        .map(|n| n.to_string())
        .unwrap_or_else(|_| format!("0x{}", hex))
}

pub fn hex_to_u8(hex: &str) -> u8 {
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() { return 0; }
    u8::from_str_radix(trimmed, 16).unwrap_or(0)
}

fn is_zero_hex(hex: &str) -> bool {
    hex.chars().all(|c| c == '0')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repo_hash() {
        // Must match keccak256(abi.encodePacked("github:acme/api"))
        let hash = repo_hash("acme", "api");
        let expected = keccak256(b"github:acme/api");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_create_bounty_selector() {
        let data = encode_create_bounty(&[0u8; 32], 86400, false);
        // keccak256("createBounty(bytes32,uint256,bool)") first 4 bytes
        let sel = selector("createBounty(bytes32,uint256,bool)");
        assert_eq!(&data[..4], &sel);
        assert_eq!(data.len(), 4 + 32 + 32 + 32); // selector + 3 params
    }

    #[test]
    fn test_set_repo_info_encoding() {
        let data = encode_set_repo_info(1, "acme", "api", 12345);
        let sel = selector("setRepoInfo(uint256,string,string,uint256)");
        assert_eq!(&data[..4], &sel);
        // Head: 4 + 4*32 = 132 bytes minimum
        assert!(data.len() >= 132);
        // bounty_id = 1 in slot 0
        assert_eq!(data[4 + 31], 1);
    }

    #[test]
    fn test_set_audit_config_encoding() {
        let data = encode_set_audit_config(1, 0x01, 0, 3, 0);
        let sel = selector("setAuditConfig(uint256,uint8,uint8,uint8,uint256)");
        assert_eq!(&data[..4], &sel);
        assert_eq!(data.len(), 4 + 5 * 32);
    }

    #[test]
    fn test_set_delivery_config_encoding() {
        let pubkey = [0xAA; 32];
        let policy = [0xBB; 32];
        let data = encode_set_delivery_config(1, &pubkey, &policy, 1);
        let sel = selector("setDeliveryConfig(uint256,bytes32,bytes32,uint8)");
        assert_eq!(&data[..4], &sel);
        assert_eq!(data.len(), 4 + 4 * 32);
        // delivery_mode = 1 (RequesterOnly) in last slot
        assert_eq!(data[4 + 3 * 32 + 31], 1);
    }

    #[test]
    fn test_encode_cancel_bounty() {
        let data = encode_cancel_bounty(42);
        let sel = selector("cancelBounty(uint256)");
        assert_eq!(&data[..4], &sel);
        assert_eq!(data.len(), 4 + 32);
        // bounty_id = 42
        assert_eq!(data[4 + 31], 42);
    }

    #[test]
    fn test_encode_top_up_bounty() {
        let data = encode_top_up_bounty(42);
        let sel = selector("topUpBounty(uint256)");
        assert_eq!(&data[..4], &sel);
        assert_eq!(data.len(), 4 + 32);
        assert_eq!(data[4 + 31], 42);
    }

    #[test]
    fn test_encode_dispute_audit() {
        let data = encode_dispute_audit(7);
        let sel = selector("disputeAudit(uint256,bytes32)");
        assert_eq!(&data[..4], &sel);
        // uint256 + bytes32 = 64 bytes of params
        assert_eq!(data.len(), 4 + 32 + 32);
        // audit_id = 7 in first param
        assert_eq!(data[4 + 31], 7);
        // second param is all zeros (bytes32(0))
        assert!(data[4 + 32..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encode_release_bounty_claim() {
        let data = encode_release_bounty_claim(42);
        let sel = selector("releaseBountyClaim(uint256)");
        assert_eq!(&data[..4], &sel);
        assert_eq!(data.len(), 4 + 32);
        assert_eq!(data[4 + 31], 42);
    }

    #[test]
    fn test_encode_claim_audit_payout() {
        let data = encode_claim_audit_payout(7);
        let sel = selector("claimAuditPayout(uint256)");
        assert_eq!(&data[..4], &sel);
        assert_eq!(data.len(), 4 + 32);
        assert_eq!(data[4 + 31], 7);
    }

    #[test]
    fn test_encode_is_registered_performer() {
        let encoded = encode_is_registered_performer("0x1234567890abcdef1234567890abcdef12345678");
        let without_prefix = encoded.trim_start_matches("0x");
        // No spaces, valid hex
        assert!(without_prefix.chars().all(|c| c.is_ascii_hexdigit()));
        // Correct selector
        let sel = selector("registeredPerformers(address)");
        let sel_hex = hex::encode(sel);
        assert!(without_prefix.starts_with(&sel_hex));
        // Correct length: 8 (selector) + 64 (address)
        assert_eq!(without_prefix.len(), 8 + 64);
    }

    #[test]
    fn test_encode_get_reputation() {
        let encoded = encode_get_reputation("0x1234567890abcdef1234567890abcdef12345678");
        let without_prefix = encoded.trim_start_matches("0x");
        assert!(without_prefix.chars().all(|c| c.is_ascii_hexdigit()));
        let sel = selector("getPerformer(address)");
        let sel_hex = hex::encode(sel);
        assert!(without_prefix.starts_with(&sel_hex));
        assert_eq!(without_prefix.len(), 8 + 64);
    }

    #[test]
    fn test_hex_to_decimal_string() {
        assert_eq!(hex_to_decimal_string("0000000000000000000000000000000000000000000000000000000000000001"), "1");
        assert_eq!(hex_to_decimal_string("0000000000000000000000000000000000000000000000000de0b6b3a7640000"), "1000000000000000000");
        assert_eq!(hex_to_decimal_string("0000000000000000000000000000000000000000000000000000000000000000"), "0");
    }

    #[test]
    fn test_is_zero_result() {
        assert!(is_zero_result("0x0000000000000000000000000000000000000000000000000000000000000000"));
        assert!(is_zero_result("0x"));
        assert!(!is_zero_result("0x0000000000000000000000000000000000000000000000000000000000000001"));
    }

    #[test]
    fn test_decode_event_unknown() {
        let log = serde_json::json!({
            "topics": ["0xabc"],
            "data": "0x1234",
            "blockNumber": "0xa",
            "transactionHash": "0xdeadbeef"
        });
        let event = decode_event("unknown.event", &log);
        assert_eq!(event["event"], "unknown.event");
        assert_eq!(event["block"], 10);
    }

    #[test]
    fn test_encode_address() {
        let encoded = encode_address("0x1234567890abcdef1234567890abcdef12345678");
        assert_eq!(encoded.len(), 32);
        assert!(encoded[..12].iter().all(|&b| b == 0));
        assert_eq!(hex::encode(&encoded[12..]), "1234567890abcdef1234567890abcdef12345678");
    }

    #[test]
    fn test_encode_request_claim() {
        let config_hash = [0xAA; 32];
        let data = encode_request_claim(42, &config_hash);
        let sel = selector("requestClaim(uint256,bytes32)");
        assert_eq!(&data[..4], &sel);
        assert_eq!(data.len(), 4 + 32 + 32);
        assert_eq!(data[4 + 31], 42);
        assert_eq!(&data[4 + 32..4 + 64], &config_hash);
    }

    #[test]
    fn test_encode_get_pending_claim() {
        let encoded = encode_get_pending_claim(42, "0x1234567890abcdef1234567890abcdef12345678");
        let without_prefix = encoded.trim_start_matches("0x");
        assert!(without_prefix.chars().all(|c| c.is_ascii_hexdigit()));
        let sel = selector("getPendingClaim(uint256,address)");
        let sel_hex = hex::encode(sel);
        assert!(without_prefix.starts_with(&sel_hex));
        assert_eq!(without_prefix.len(), 8 + 64 + 64);
    }

    #[test]
    fn test_claim_event_topics() {
        let topic = claim_requested_topic();
        assert!(topic.starts_with("0x"));
        assert_eq!(topic.len(), 66);
        let topic2 = bounty_claim_acquired_topic();
        assert!(topic2.starts_with("0x"));
        let topic3 = claim_rejected_topic();
        assert!(topic3.starts_with("0x"));
        assert_ne!(topic, topic2);
        assert_ne!(topic, topic3);
        assert_ne!(topic2, topic3);
    }
}
