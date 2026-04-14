use tiny_keccak::{Hasher, Keccak};

/// Compute keccak256 hash of input bytes.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// Compute first 4 bytes of keccak256 (Solidity function selector).
pub fn selector(sig: &str) -> [u8; 4] {
    let hash = keccak256(sig.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Derive Ethereum address from secp256k1 private key hex.
pub fn private_key_to_address(private_key_hex: &str) -> anyhow::Result<String> {
    use k256::ecdsa::SigningKey;
    let key_bytes =
        hex::decode(private_key_hex.trim_start_matches("0x")).map_err(|e| anyhow::anyhow!(e))?;
    let signing_key =
        SigningKey::from_bytes((&key_bytes[..]).into()).map_err(|e| anyhow::anyhow!(e))?;
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_encoded_point(false);
    let public_key_bytes = &public_key.as_bytes()[1..]; // skip 0x04 prefix
    let hash = keccak256(public_key_bytes);
    Ok(format!("0x{}", hex::encode(&hash[12..])))
}

/// Load X25519 private key from explicit path or auto-match against ~/.pora/keys/.
// SECURITY: private key never leaves local machine. Only loaded into memory for decryption.
pub fn load_private_key(
    explicit_path: Option<&str>,
    onchain_pubkey: Option<&str>,
) -> anyhow::Result<[u8; 32]> {
    use x25519_dalek::{PublicKey, StaticSecret};

    if let Some(path) = explicit_path {
        return read_key_file(path);
    }

    let keys_dir = crate::config::keys_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine ~/.pora/keys/ path"))?;

    let entries = std::fs::read_dir(&keys_dir).map_err(|e| {
        anyhow::anyhow!(
            "Cannot read {}: {}. Generate a key with 'pora request submit'",
            keys_dir.display(),
            e
        )
    })?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e == "key").unwrap_or(false) {
            if let Ok(secret_bytes) = read_key_file(path.to_str().unwrap_or("")) {
                let secret = StaticSecret::from(secret_bytes);
                let pubkey = PublicKey::from(&secret);
                let pubkey_hex = hex::encode(pubkey.as_bytes());

                if let Some(expected) = onchain_pubkey {
                    let expected_clean = expected.trim_start_matches("0x").to_lowercase();
                    // WHY: on-chain pubkey is bytes32 (64 hex chars, right-padded).
                    //      X25519 pubkey is 32 bytes. Compare the first 32 bytes.
                    if expected_clean.starts_with(&pubkey_hex) {
                        return Ok(secret_bytes);
                    }
                }
            }
        }
    }

    anyhow::bail!("No matching private key found in ~/.pora/keys/. Use --key to specify explicitly.")
}

fn read_key_file(path: &str) -> anyhow::Result<[u8; 32]> {
    let content =
        std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("Cannot read {}: {}", path, e))?;
    let hex_str = content.trim().trim_start_matches("0x");
    let bytes =
        hex::decode(hex_str).map_err(|e| anyhow::anyhow!("Invalid key hex in {}: {}", path, e))?;
    if bytes.len() != 32 {
        anyhow::bail!("Key in {} is {} bytes, expected 32", path, bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Full decryption pipeline: X25519 → HKDF-SHA256 → AES-256-GCM.
// SECURITY: shared secret is derived fresh and discarded after use.
// TRUST: ephemeral pubkey came from the manifest, which is hash-verified against on-chain anchor.
pub fn decrypt_delivery(
    secret_key: &[u8; 32],
    ephemeral_pubkey_hex: &str,
    nonce_hex: &str,
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    // Step 1: X25519 key exchange
    let ephemeral_bytes = hex::decode(ephemeral_pubkey_hex.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid ephemeral pubkey: {}", e))?;
    if ephemeral_bytes.len() != 32 {
        anyhow::bail!("Ephemeral pubkey is {} bytes, expected 32", ephemeral_bytes.len());
    }
    let mut ephem_arr = [0u8; 32];
    ephem_arr.copy_from_slice(&ephemeral_bytes);

    let secret = StaticSecret::from(*secret_key);
    let their_public = PublicKey::from(ephem_arr);
    let shared_secret = secret.diffie_hellman(&their_public);

    // Step 2: HKDF-SHA256 key derivation
    // WHY: raw X25519 output is not suitable as an AES key directly.
    //      HKDF extracts entropy and expands to the required key length.
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hkdf.expand(b"pora-delivery-v1", &mut aes_key)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {}", e))?;

    // Step 3: AES-256-GCM decrypt
    let nonce_bytes = hex::decode(nonce_hex.trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("Invalid nonce: {}", e))?;
    if nonce_bytes.len() != 12 {
        anyhow::bail!("Nonce is {} bytes, expected 12", nonce_bytes.len());
    }

    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|e| anyhow::anyhow!("AES-GCM init: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("AES-GCM decryption failed: authentication tag mismatch"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256_known_value() {
        let hash = keccak256(b"hello");
        assert_eq!(
            hex::encode(hash),
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};
        use hkdf::Hkdf;
        use sha2::Sha256;
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);

        // Simulate TEE-side encryption
        let ephemeral_secret_bytes: [u8; 32] = [
            0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
            0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05,
            0x04, 0x03, 0x02, 0x01,
        ];
        let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        let tee_shared = ephemeral_secret.diffie_hellman(&public);
        let hkdf = Hkdf::<Sha256>::new(None, tee_shared.as_bytes());
        let mut aes_key = [0u8; 32];
        hkdf.expand(b"pora-delivery-v1", &mut aes_key).unwrap();

        let nonce_bytes = [0x01u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = b"vulnerability report: SQL injection in login.py line 42";
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        let result = decrypt_delivery(
            &secret_bytes,
            &hex::encode(ephemeral_public.as_bytes()),
            &hex::encode(nonce_bytes),
            &ciphertext,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), plaintext.to_vec());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};
        use hkdf::Hkdf;
        use sha2::Sha256;
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret_bytes: [u8; 32] = [0x01; 32];
        let wrong_secret: [u8; 32] = [0xff; 32];
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);

        let ephemeral_secret_bytes: [u8; 32] = [0x02; 32];
        let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        let tee_shared = ephemeral_secret.diffie_hellman(&public);
        let hkdf = Hkdf::<Sha256>::new(None, tee_shared.as_bytes());
        let mut aes_key = [0u8; 32];
        hkdf.expand(b"pora-delivery-v1", &mut aes_key).unwrap();

        let nonce_bytes = [0x01u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, b"secret".as_ref()).unwrap();

        let result = decrypt_delivery(
            &wrong_secret,
            &hex::encode(ephemeral_public.as_bytes()),
            &hex::encode(nonce_bytes),
            &ciphertext,
        );
        assert!(result.is_err());
    }
}
